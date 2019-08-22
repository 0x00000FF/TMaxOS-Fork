
/* xorriso - creates, loads, manipulates and burns ISO 9660 filesystem images.

   Copyright 2007-2016 Thomas Schmitt, <scdbackup@gmx.net>

   Provided under GPL version 2 or later.

   This file contains functions which operate on ISO images and their
   global properties.
*/

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

#include <ctype.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>

#include <sys/wait.h>

#include "xorriso.h"
#include "xorriso_private.h"
#include "xorrisoburn.h"

#include "lib_mgt.h"
#include "iso_img.h"
#include "iso_tree.h"
#include "drive_mgt.h"


int Xorriso_set_ignore_aclea(struct XorrisO *xorriso, int flag)
{
 int ret, hflag;
 IsoImage *volume;

 ret= Xorriso_get_volume(xorriso, &volume, 1); 
 if(ret<=0)
   return(ret);
 hflag= (~xorriso->do_aaip) & 1;
 if((xorriso->ino_behavior & (1 | 2)) && !(xorriso->do_aaip & (4 | 16)))
   hflag|= 2; 
 if(xorriso->do_aaip & 1024)
   hflag|= 8;
 iso_image_set_ignore_aclea(volume, hflag);
 return(1);
}


int Xorriso_update_volid(struct XorrisO *xorriso, int flag)
{
 int gret, sret= 1;

 gret= Xorriso_get_volid(xorriso, xorriso->loaded_volid, 0);
 if(gret<=0 || (!xorriso->volid_default) || xorriso->loaded_volid[0]==0)
   sret= Xorriso_set_volid(xorriso, xorriso->volid, 1);
 return(gret>0 && sret>0);
} 
 

int Xorriso_create_empty_iso(struct XorrisO *xorriso, int flag)
{
 int ret;
 IsoImage *volset;
 struct isoburn_read_opts *ropts;
 struct burn_drive_info *dinfo= NULL;
 struct burn_drive *drive= NULL;

 if(xorriso->out_drive_handle != NULL) {
   ret= Xorriso_get_drive_handles(xorriso, &dinfo, &drive,
                                  "on attempt to attach volset to drive", 2);
   if(ret<=0)
     return(ret);
 }
 if(xorriso->in_volset_handle!=NULL) {
   iso_image_unref((IsoImage *) xorriso->in_volset_handle);
   xorriso->in_volset_handle= NULL;
   Sectorbitmap_destroy(&(xorriso->in_sector_map), 0);
   Xorriso_destroy_di_array(xorriso, 0);
   Xorriso_destroy_hln_array(xorriso, 0);
   xorriso->loaded_volid[0]= 0;
   xorriso->volset_change_pending= 0;
   xorriso->boot_count= 0;
   xorriso->no_volset_present= 0;
 }

 ret= isoburn_ropt_new(&ropts, 0);
 if(ret<=0)
   return(ret);
 /* Note: no return before isoburn_ropt_destroy() */
 isoburn_ropt_set_extensions(ropts, isoburn_ropt_pretend_blank);
 isoburn_ropt_set_input_charset(ropts, xorriso->in_charset);
 isoburn_ropt_set_data_cache(ropts, 1, 1, 0);
 isoburn_set_read_pacifier(drive, NULL, NULL);
 isoburn_ropt_set_truncate_mode(ropts, 1, xorriso->file_name_limit);

 ret= isoburn_read_image(drive, ropts, &volset);
 Xorriso_process_msg_queues(xorriso,0);
 isoburn_ropt_destroy(&ropts, 0);
 if(ret<=0) {
   sprintf(xorriso->info_text, "Failed to create new empty ISO image object");
   Xorriso_report_iso_error(xorriso, "", ret, xorriso->info_text, 0, "FATAL",
                            0);
   return(-1);
 }
 xorriso->in_volset_handle= (void *) volset;
 xorriso->in_sector_map= NULL;
 Xorriso_update_volid(xorriso, 0);
 xorriso->volset_change_pending= 0;
 xorriso->boot_count= 0;
 xorriso->system_area_clear_loaded=
                    (strcmp(xorriso->system_area_disk_path, "/dev/zero") == 0);
 xorriso->no_volset_present= 0;
 return(1);
}


int Xorriso_record_boot_info(struct XorrisO *xorriso, int flag)
{
 int ret;
 struct burn_drive_info *dinfo;
 struct burn_drive *drive;
 IsoImage *image;
 ElToritoBootImage *bootimg;
 IsoFile *bootimg_node;
 IsoBoot *bootcat_node;

 xorriso->loaded_boot_bin_lba= -1;
 xorriso->loaded_boot_cat_path[0]= 0;
 ret= Xorriso_get_drive_handles(xorriso, &dinfo, &drive,
                                "on attempt to record boot LBAs", 0);
 if(ret<=0)
   return(0);
 image= isoburn_get_attached_image(drive);
 if(image == NULL)
   return(0);
 ret= iso_image_get_boot_image(image, &bootimg,
                               &bootimg_node, &bootcat_node);
 iso_image_unref(image); /* release obtained reference */
 if(ret != 1)
   return(0);
 if(bootimg_node != NULL)
   Xorriso__file_start_lba((IsoNode *) bootimg_node,
                           &(xorriso->loaded_boot_bin_lba), 0);
 if(bootcat_node != NULL)
   Xorriso_path_from_lba(xorriso, (IsoNode *) bootcat_node, 0,
                         xorriso->loaded_boot_cat_path, 0);
 return(1);
}


int Xorriso_assert_volid(struct XorrisO *xorriso, int msc1, int flag)
{
 int ret, image_blocks;
 char volid[33];
 struct burn_drive_info *dinfo;
 struct burn_drive *drive;

 if(xorriso->assert_volid[0] == 0)
   return(1);
 ret= Xorriso_get_drive_handles(xorriso, &dinfo, &drive,
                                "on attempt to perform -assert_volid", 0);
 if(ret<=0)
   return(0);
 ret= isoburn_read_iso_head(drive, msc1, &image_blocks, volid, 1);
 Xorriso_process_msg_queues(xorriso,0);
 if(ret <= 0) {
   sprintf(xorriso->info_text,
           "-assert_volid: Cannot determine Volume Id at LBA %d.", msc1);
   Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0,
                       xorriso->assert_volid_sev, 0);
   return(0);
 }
 ret= Sregex_match(xorriso->assert_volid, volid, 0);
 if(ret < 0)
   return(2);
 if(ret == 0) {
   strcpy(xorriso->info_text,
          "-assert_volid: Volume id does not match pattern: ");
   Text_shellsafe(xorriso->assert_volid, xorriso->info_text, 1);
   strcat(xorriso->info_text, " <> ");
   Text_shellsafe(volid, xorriso->info_text, 1);
   Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0,
                       xorriso->assert_volid_sev, 0);
   return(0);
 }
 return(ret);
}


/* @return <0 yes , 0 no , <0 error */
int Xorriso_is_isohybrid(struct XorrisO *xorriso, IsoFile *bootimg_node,
                         int flag)
{
 int ret;
 unsigned char buf[68];
 void *data_stream= NULL;

 ret= Xorriso_iso_file_open(xorriso, "", (void *) bootimg_node,
                            &data_stream, 1);
 if(ret <= 0)
   return(-1);
 ret= Xorriso_iso_file_read(xorriso, data_stream, (char *) buf, 68, 0);
 Xorriso_iso_file_close(xorriso, &data_stream, 0);
 if(ret <= 0)
   return(0);
 if(buf[64] == 0xfb && buf[65] == 0xc0 && buf[66] == 0x78 && buf[67] == 0x70)
   return(1);
 return(0);
}


int Xorriso_image_has_md5(struct XorrisO *xorriso, int flag)
{
 int ret;
 IsoImage *image;
 uint32_t start_lba, end_lba;
 char md5[16];

 ret= Xorriso_get_volume(xorriso, &image, 0);
 if(ret<=0)
   return(ret);
 ret= iso_image_get_session_md5(image, &start_lba, &end_lba, md5, 0);
 Xorriso_process_msg_queues(xorriso,0);
 if(ret <= 0)
   return(0);
 return(1);
}


static const char *un0(const char *text)
{
 if(text == NULL)
   return("");
 return(text);
}


static int Xorriso_report_pvd_time(struct XorrisO *xorriso, char *head,
                                   char *pvd_time, int flag)
{
 char *msg, hr[17];
 int at;

 msg= xorriso->result_line;
 strncpy(hr, pvd_time, 16);
 hr[16]= 0;
 sprintf(msg, "%s %s\n", head, hr);
 Xorriso_result(xorriso,0);
 if(pvd_time[16] != 0) {
   at= abs(pvd_time[16]);
   sprintf(msg, "%2.2s. Time Zone: %c%-2.2d:%-2.2d\n", head,
           pvd_time[16] > 0 ? '+' : '-', at / 4, (at - (at / 4) * 4) * 15);
   Xorriso_result(xorriso,0);
 }
 return(1);
}


int Xorriso_pvd_info(struct XorrisO *xorriso, int flag)
{
 int ret, msc1= -1, msc2, i;
 IsoImage *image;
 struct burn_drive_info *dinfo;
 struct burn_drive *drive;
 char *msg, block_head[8], *crt, *mdt, *ext, *eft;
 off_t head_count;

 msg= xorriso->result_line;
 ret= Xorriso_get_volume(xorriso, &image, 0);
 if(ret<=0)
   return(ret);
 ret= Xorriso_get_drive_handles(xorriso, &dinfo, &drive, "", 16);
 if(ret > 0) {
   ret= Xorriso_msinfo(xorriso, &msc1, &msc2, 1 | 4);
   if(ret<0)
     return(ret);
   Xorriso_toc(xorriso, 128);
   if(msc1 >= 0) {
     for(i = msc1 + 16; i < msc1 + 32; i++) {
       ret= burn_read_data(drive, (off_t) i * (off_t) 2048, block_head,
                           (off_t) sizeof(block_head), &head_count, 2);
       if(ret <= 0) {
         i= msc1 + 32;
     break;
       }
       if(block_head[0] == 1 && strncmp(block_head + 1, "CD001", 5) == 0)
     break;
     }
     if(i < msc1 + 32) {
       sprintf(msg, "PVD address  : %ds\n", i);
       Xorriso_result(xorriso,0);
     }
   }
 }
 sprintf(msg, "Volume Id    : %s\n", un0(iso_image_get_volume_id(image)));
 Xorriso_result(xorriso,0);
 sprintf(msg, "Volume Set Id: %s\n", xorriso->volset_id);
 Xorriso_result(xorriso,0);
 sprintf(msg, "Publisher Id : %s\n", xorriso->publisher);
 Xorriso_result(xorriso,0);
 sprintf(msg, "Preparer Id  : %s\n",
         un0(iso_image_get_data_preparer_id(image)));
 Xorriso_result(xorriso,0);
 sprintf(msg, "App Id       : %s\n", xorriso->application_id);
 Xorriso_result(xorriso,0);
 sprintf(msg, "System Id    : %s\n", xorriso->system_id);
 Xorriso_result(xorriso,0);
 sprintf(msg, "CopyrightFile: %s\n", xorriso->copyright_file);
 Xorriso_result(xorriso,0);
 sprintf(msg, "Abstract File: %s\n", xorriso->abstract_file);
 Xorriso_result(xorriso,0);
 sprintf(msg, "Biblio File  : %s\n", xorriso->biblio_file);
 Xorriso_result(xorriso,0);

 ret= iso_image_get_pvd_times(image, &crt, &mdt, &ext, &eft);
 if(ret != ISO_SUCCESS)
   crt= mdt= ext= eft= "                "; /* Need 17 bytes. Last byte 0. */
 Xorriso_report_pvd_time(xorriso, "Creation Time:", crt, 0);
 Xorriso_report_pvd_time(xorriso, "Modif. Time  :", mdt, 0);
 Xorriso_report_pvd_time(xorriso, "Expir. Time  :", ext, 0);
 Xorriso_report_pvd_time(xorriso, "Eff. Time    :", eft, 0);
 return(1);
}


/* @param flag bit0= do not mark image as changed */
int Xorriso_set_volid(struct XorrisO *xorriso, char *volid, int flag)
{
 int ret;
 IsoImage *volume;

 if(xorriso->in_volset_handle == NULL)
   return(2);
 ret= Xorriso_get_volume(xorriso, &volume, 0);
 if(ret<=0)
   return(ret);
 if(iso_image_get_volume_id(volume) == NULL ||
    strcmp(iso_image_get_volume_id(volume), volid) != 0)
   if(!(flag&1))
     Xorriso_set_change_pending(xorriso, 1);
 iso_image_set_volume_id(volume, volid);
 Xorriso_process_msg_queues(xorriso,0);
 sprintf(xorriso->info_text,"Volume ID: '%s'",iso_image_get_volume_id(volume));
 Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "DEBUG", 0);
 return(1);
}


int Xorriso_get_volid(struct XorrisO *xorriso, char volid[33], int flag)
{
 int ret;
 IsoImage *volume;

 ret= Xorriso_get_volume(xorriso, &volume, 0);
 if(ret<=0)
   return(ret);
 strncpy(volid, iso_image_get_volume_id(volume), 32);
 volid[32]= 0;
 return(1);
}


/* 
 bit0= do only report non-default settings
 bit1= do only report to fp
 bit2= is_default
 bit3= append -boot_image any next
 bit4= concentrate boot options
 bit5= override load_size by "full"
*/
int Xorriso_boot_item_status(struct XorrisO *xorriso, char *cat_path,
                             char *bin_path, int platform_id,
                             int patch_isolinux, int emul, off_t load_size,
                             unsigned char *id_string,
                             unsigned char *selection_crit, char *form,
                             char *filter, FILE *fp, int flag)
{
 int is_default, no_defaults, i, is_default_id= 0, ret;
 char *line, *bspec= NULL, zeros[28], *partition_entry;
 off_t file_size;
 struct stat stbuf;

 Xorriso_alloc_meM(bspec, char, SfileadrL + 80);

 no_defaults= flag & 1;
 line= xorriso->result_line;
 if(flag & 32)
   load_size= -1;

 if((flag & 16) && bin_path[0] != 0) {
   /* Concentrate boot options. */
   memset(zeros, 0, 28);
   if(memcmp(id_string, zeros, 28) == 0 &&
      memcmp(selection_crit, zeros, 20) == 0)
     is_default_id= 1;

   /* -boot_image isolinux dir= ... */
   bspec[0]= 0;
   if(strcmp(form, "isolinux") != 0 && strcmp(form, "any") != 0)
     ;
   else if(strcmp(bin_path, "/isolinux.bin") == 0 &&
      strcmp(cat_path, "/boot.cat") == 0)
     strcpy(bspec, "dir=/");
   else if(strcmp(bin_path, "/isolinux/isolinux.bin") == 0 &&
           strcmp(cat_path, "/isolinux/boot.cat") == 0)
     strcpy(bspec, "dir=/isolinux");
   else if(strcmp(xorriso->boot_image_bin_path,
                  "/boot/isolinux/isolinux.bin") == 0
           && strcmp(xorriso->boot_image_cat_path,
                     "/boot/isolinux/boot.cat") == 0)
     strcpy(bspec, "dir=/boot/isolinux");
   memset(zeros, 0, 28);
   if(bspec[0] && platform_id == 0 && (patch_isolinux & 0x3ff) == 1 &&
      load_size == 2048 && is_default_id && emul == 0) {
     sprintf(line, "-boot_image isolinux %s\n", bspec);
     Xorriso_status_result(xorriso,filter,fp,flag&2); 
     {ret= 1; goto ex;};
   }

   file_size= 0;
   ret= Xorriso_iso_lstat(xorriso, bin_path, &stbuf, 2 | 4);
   if(ret == 0) {
     file_size= ((stbuf.st_size / (off_t) 512) +
                !!(stbuf.st_size % (off_t) 512)) * 512;
     if(flag & 32)
       load_size= file_size * 512;
   }
   if(platform_id == 0xef && (patch_isolinux & 0x3ff) == 0 &&
      load_size / 512 == file_size && is_default_id && emul == 0) {
     sprintf(line, "-boot_image any efi_path=");
     Text_shellsafe(bin_path, line, 1);
     strcat(line, "\n");
     Xorriso_status_result(xorriso,filter,fp,flag&2);
     {ret= 1; goto ex;};
   }
 }

 is_default= (bin_path[0] == 0) || (flag & 4);
 sprintf(line, "-boot_image %s bin_path=", form);
 Text_shellsafe(bin_path, line, 1);
 strcat(line, "\n");
 if(!(is_default && no_defaults))
   Xorriso_status_result(xorriso,filter,fp,flag&2);

 is_default= (emul == 0);
 sprintf(line, "-boot_image %s emul_type=%s\n",
      form, emul == 2 ? "diskette" : emul == 1 ? "hard_disk" : "no_emulation");
 if(!(is_default && no_defaults))
   Xorriso_status_result(xorriso,filter,fp,flag&2);
 
 is_default= (platform_id == 0 || (flag & 4));
 sprintf(line, "-boot_image %s platform_id=0x%-2.2x\n", form, platform_id);
 if(!(is_default && no_defaults))
   Xorriso_status_result(xorriso,filter,fp,flag&2); 

 is_default= ((patch_isolinux & 1) == 0 || bin_path[0] == 0 || (flag & 4));
 sprintf(line, "-boot_image %s boot_info_table=%s\n",
               (patch_isolinux & 2) ? "grub" : form,
               (patch_isolinux & 1) ? "on" : "off");
 if(!(is_default && no_defaults))
   Xorriso_status_result(xorriso,filter,fp,flag&2); 
 
 is_default= ((patch_isolinux & 512) == 0 || bin_path[0] == 0 || (flag & 4));
 sprintf(line, "-boot_image grub grub2_boot_info=%s\n",
               (patch_isolinux & 512) ? "on" : "off");
 if(!(is_default && no_defaults))
   Xorriso_status_result(xorriso,filter,fp,flag&2); 
 
 if(flag & 32) {
   is_default= 0;
   sprintf(line, "-boot_image %s load_size=full", form);
 } else {
   is_default= (load_size == 2048 || (flag & 4));
   sprintf(line, "-boot_image %s load_size=%lu\n",
           form, (unsigned long) load_size);
 }
 if(!(is_default && no_defaults))
   Xorriso_status_result(xorriso,filter,fp,flag&2); 

 is_default= 1;
 if(!(flag & 4))
   for(i= 0; i < 20; i++)
     if(selection_crit[i])
       is_default= 0;
 sprintf(line, "-boot_image %s sel_crit=", form);
 for(i= 0; i < 20; i++)
   sprintf(line + strlen(line), "%-2.2X", (unsigned int) selection_crit[i]);
 strcat(line, "\n");
 if(!(is_default && no_defaults))
   Xorriso_status_result(xorriso,filter,fp,flag&2); 

 is_default= 1;
 if(!(flag & 4))
   for(i= 0; i < 28; i++)
     if(id_string[i])
       is_default= 0;
 sprintf(line, "-boot_image %s id_string=", form);
 for(i= 0; i < 28; i++)
   sprintf(line + strlen(line), "%-2.2X", (unsigned int) id_string[i]);
 strcat(line, "\n");
 if(!(is_default && no_defaults))
   Xorriso_status_result(xorriso,filter,fp,flag&2); 

 is_default= 1;
 partition_entry= "";
 if((patch_isolinux & 0x0fc) == (1 << 2))
   partition_entry= "gpt_basdat";
 else if((patch_isolinux & 0x0fc) == (2 << 2))
   partition_entry= "gpt_hfsplus";
 if(partition_entry[0]) {
   sprintf(line, "-boot_image isolinux partition_entry=%s\n", partition_entry);
   Xorriso_status_result(xorriso, filter, fp, flag & 2);
   is_default= 0;
 }
 if(patch_isolinux & (1 << 8)) {
   sprintf(line, "-boot_image isolinux partition_entry=apm_hfsplus\n");
   Xorriso_status_result(xorriso, filter, fp, flag & 2);
   is_default= 0;
 }
 if(is_default && !no_defaults) {
   sprintf(line, "-boot_image isolinux partition_entry=off\n");
   Xorriso_status_result(xorriso, filter, fp, flag & 2);
 }
 
 ret= 1; 
ex:;
 Xorriso_free_meM(bspec);
 return(ret); 
}


int Xorriso_status_hppa(struct XorrisO *xorriso, char *what, char *value,
                        char *filter, FILE *fp, int flag)
{
 char *line;

 line= xorriso->result_line;
 if(value == NULL)
   return(1);
 sprintf(line, "-boot_image any hppa_%s=", what);
 Text_shellsafe(value, line, 1);
 strcat(line, "\n");
 Xorriso_status_result(xorriso, filter, fp, flag & 2);
 return(1);
}


/* 
 bit0= do only report non-default settings
 bit1= do only report to fp
*/
int Xorriso_boot_status_non_mbr(struct XorrisO *xorriso, IsoImage *image,
                                char *filter, FILE *fp, int flag)
{
 int i, num_boots, sa_type;
 char *paths[15], *line;
 int ret;
 char num[4];
 char *cmdline, *bootloader, *kernel_32, *kernel_64, *ramdisk;

 line= xorriso->result_line;

 sa_type= (xorriso->system_area_options & 0xfc) >> 2;
 if(sa_type == 3) {
   sprintf(line, "-boot_image any sparc_label=");
   Text_shellsafe(xorriso->ascii_disc_label, line, 1);
   strcat(line, "\n");
   Xorriso_status_result(xorriso, filter, fp, flag & 2);
   sprintf(line, "-boot_image grub grub2_sparc_core=");
   Text_shellsafe(xorriso->grub2_sparc_core, line, 1);
   strcat(line, "\n");
   Xorriso_status_result(xorriso, filter, fp, flag & 2);
   return(0);
 } else if(sa_type == 1 || sa_type == 2) {
   num_boots= iso_image_get_mips_boot_files(image, paths, 0);
   Xorriso_process_msg_queues(xorriso, 0);
   if(num_boots > 0) {
     if(sa_type == 2)
       num_boots= 1;
     for(i= 0; i < num_boots; i++) {
       sprintf(line, "-boot_image any mips%s_path=", sa_type ==2 ? "el" : "");
       Text_shellsafe(paths[i], line, 1);
       strcat(line, "\n");
       Xorriso_status_result(xorriso, filter, fp, flag & 2);
     }
   }
   return(num_boots);
 } else if(sa_type == 4 || sa_type == 5) {
   ret= iso_image_get_hppa_palo(image, &cmdline, &bootloader, &kernel_32,
                                &kernel_64, &ramdisk);
   if(ret == 1) {
     Xorriso_status_hppa(xorriso, "cmdline", cmdline, filter, fp, 0);
     Xorriso_status_hppa(xorriso, "bootloader", bootloader, filter, fp, 0);
     Xorriso_status_hppa(xorriso, "kernel_32", kernel_32, filter, fp, 0);
     Xorriso_status_hppa(xorriso, "kernel_64", kernel_64, filter, fp, 0);
     Xorriso_status_hppa(xorriso, "ramdisk", ramdisk, filter, fp, 0);
     sprintf(num, "%d", sa_type);
     Xorriso_status_hppa(xorriso, "hdrversion", num, filter, fp, 0);
   }
   return(0);
 } else if(sa_type == 6) {
   ret= iso_image_get_alpha_boot(image, &bootloader);
   if (ret == 1 && bootloader != NULL) {
     sprintf(line, "-boot_image any alpha_boot=");
     Text_shellsafe(bootloader, line, 1);
     strcat(line, "\n");
     Xorriso_status_result(xorriso, filter, fp, flag & 2);
   }
   return(0);
 }
 return(0);
}


/* 
 bit0= do only report non-default settings
 bit1= do only report to fp
*/
int Xorriso_append_part_status(struct XorrisO *xorriso, IsoImage *image,
                             char *filter, FILE *fp, int flag)
{
 int i, is_default;

 is_default= (xorriso->appended_as_gpt == 0);
 sprintf(xorriso->result_line, "-boot_image any appended_part_as=%s\n",
         xorriso->appended_as_gpt ? "gpt" : "mbr");
 if(!(is_default && (flag & 1)))
   Xorriso_status_result(xorriso, filter, fp, flag & 2);
 for(i= 0; i < Xorriso_max_appended_partitionS; i++) {
   if(xorriso->appended_partitions[i] == NULL)
 continue;
   sprintf(xorriso->result_line, "-append_partition %d 0x%2.2x ",
           i + 1, (unsigned int) xorriso->appended_part_types[i]);
   Text_shellsafe(xorriso->appended_partitions[i], xorriso->result_line, 1);
   strcat(xorriso->result_line, "\n");
   Xorriso_status_result(xorriso, filter, fp, flag & 2);
 }
 return(1);
}


/* 
 bit0= do only report non-default settings
 bit1= do only report to fp
*/
int Xorriso_boot_image_status(struct XorrisO *xorriso, char *filter, FILE *fp,
                              int flag)
{
 int ret, i, num_boots, hflag;
 int is_default, no_defaults;
 char *path= NULL, *form= "any", *line, *hpt;
 struct burn_drive_info *dinfo;
 struct burn_drive *drive;
 IsoImage *image= NULL;
 ElToritoBootImage **boots = NULL;
 IsoFile **bootnodes = NULL;
 int platform_id, patch, load_size;
 enum eltorito_boot_media_type media_type;
 unsigned char id_string[29], sel_crit[21];

 Xorriso_alloc_meM(path, char, SfileadrL);
 line= xorriso->result_line;
 no_defaults= flag & 1;

 ret= Xorriso_get_drive_handles(xorriso, &dinfo, &drive,
                                "on attempt to print boot info", 2 | 16);
 if(ret<=0)
   goto no_image;
 image= isoburn_get_attached_image(drive);
 Xorriso_process_msg_queues(xorriso,0);
 if(image == NULL) 
   goto no_image;
 
 ret= Xorriso_boot_status_non_mbr(xorriso, image, filter, fp, flag & 3);
 if(ret < 0) /* == 0 is normal */
   {ret= 0; goto ex;}

 if(xorriso->boot_count == 0 && xorriso->boot_image_bin_path[0] == 0) {
no_image:;
   if(xorriso->patch_isolinux_image & 1) {
     sprintf(line, "-boot_image %s patch\n",
             xorriso->patch_isolinux_image & 2 ? "grub" : form);
     is_default= 0;
   } else if(xorriso->keep_boot_image) {
     sprintf(line, "-boot_image %s keep\n", form);
     is_default= 0;
   } else {
     sprintf(line, "-boot_image %s discard\n", form);
     is_default= 1;
   }
   if(!(is_default && no_defaults))
      Xorriso_status_result(xorriso,filter,fp,flag&2); 
   goto report_open_item;
 }

 is_default= (xorriso->boot_image_cat_path[0] == 0);
 sprintf(line,"-boot_image %s cat_path=", form);
 Text_shellsafe(xorriso->boot_image_cat_path, line, 1);
 strcat(line, "\n");
 if(!(is_default && no_defaults))
   Xorriso_status_result(xorriso,filter,fp,flag&2);

 is_default= !xorriso->boot_image_cat_hidden;
 hpt= Xorriso__hide_mode_text(xorriso->boot_image_cat_hidden & 63, 0);
 if(hpt != NULL)
   sprintf(line, "-boot_image %s cat_hidden=%s\n", form, hpt);
 Xorriso_free_meM(hpt);
 if(!(is_default && no_defaults))
   Xorriso_status_result(xorriso,filter,fp,flag&2);

 if(xorriso->boot_count > 0) {

   /* show attached boot image info */;

   ret= iso_image_get_all_boot_imgs(image, &num_boots, &boots, &bootnodes, 0);
   Xorriso_process_msg_queues(xorriso,0);
   if(ret == 1 && num_boots > 0) {
     for(i= 0; i < num_boots; i++) {
       ret= Xorriso_path_from_node(xorriso, (IsoNode *) bootnodes[i], path, 0);
       if(ret <= 0)
    continue;
       platform_id= el_torito_get_boot_platform_id(boots[i]);
       patch= el_torito_get_isolinux_options(boots[i], 0);
       el_torito_get_boot_media_type(boots[i], &media_type);
       load_size= el_torito_get_load_size(boots[i]) * 512;
       el_torito_get_id_string(boots[i], id_string);
       el_torito_get_selection_crit(boots[i], sel_crit);
       if(media_type == ELTORITO_FLOPPY_EMUL)
         media_type= 2;
       else if(media_type == ELTORITO_HARD_DISC_EMUL)
         media_type= 1;
       else
         media_type= 0;
       ret= Xorriso_boot_item_status(xorriso, xorriso->boot_image_cat_path,
                  path, platform_id, patch, media_type,
                  load_size, id_string, sel_crit, "any",
                  filter, fp, 16 | (flag & 3));
       if(ret <= 0)
     continue;
       sprintf(line,"-boot_image %s next\n", form);
       Xorriso_status_result(xorriso,filter,fp,flag&2);
     }
   }
 } 

 /* Show pending boot image info */
 if(strcmp(xorriso->boot_image_bin_form, "isolinux") == 0 ||
    strcmp(xorriso->boot_image_bin_form, "grub") == 0)
   form= xorriso->boot_image_bin_form;

 if(xorriso->boot_count > 0 &&
    xorriso->boot_platform_id == 0 &&
    xorriso->patch_isolinux_image == 0 &&
    xorriso->boot_image_bin_path[0] == 0 &&
    xorriso->boot_image_emul == 0 &&
    xorriso->boot_image_load_size == 4 * 512) {
   for(i= 0; i < 20; i++)
     if(xorriso->boot_selection_crit[i])
   break;
   if(i >= 20)
     for(i= 0; i < 28; i++)
       if(xorriso->boot_id_string[i])
     break;
   if(i >= 28)
     {ret= 1; goto ex;} /* Images registered, pending is still default */
 }

report_open_item:;
 hflag= 16; 
 if(xorriso->boot_platform_id == 0xef && !xorriso->boot_efi_default)
   hflag= 0;
 ret= Xorriso_boot_item_status(xorriso, xorriso->boot_image_cat_path,
             xorriso->boot_image_bin_path, xorriso->boot_platform_id,
             xorriso->patch_isolinux_image, xorriso->boot_image_emul,
             xorriso->boot_image_load_size, xorriso->boot_id_string,
             xorriso->boot_selection_crit, form,
             filter, fp, hflag | (flag & 3));
 if(ret <= 0)
   goto ex;

 ret = Xorriso_append_part_status(xorriso, image, filter, fp, flag & 3);
 if(ret <= 0)
   goto ex;

 ret= 1;
ex:
 if(boots != NULL)
   free(boots);
 if(bootnodes != NULL)
   free(bootnodes);
 if(image != NULL)
   iso_image_unref(image);
 Xorriso_free_meM(path);
 return(ret);
}


int Xorriso__append_boot_params(char *line, ElToritoBootImage *bootimg,
                                int flag)
{
 unsigned int platform_id;

 platform_id= el_torito_get_boot_platform_id(bootimg); 
 if(platform_id != 0)
   sprintf(line + strlen(line),
           " , platform_id=0x%-2.2X ", (unsigned int) platform_id);
 if(el_torito_seems_boot_info_table(bootimg, 0))
   sprintf(line + strlen(line), " , boot_info_table=on");
 if(el_torito_seems_boot_info_table(bootimg, 1))
   sprintf(line + strlen(line), " , grub2_boot_info=on");
 return(1);
}


/* @param flag bit0= no output if no boot record was found
               bit1= short form
               bit3= report to info channel (else to result channel)
*/
int Xorriso_show_boot_info(struct XorrisO *xorriso, int flag)
{
 int ret, bin_path_valid= 0, i, num_boots, sa_count;
 char *respt, *path= NULL, **sa_report= NULL, *sa_summary= NULL;
 unsigned char *lb0= NULL;
 struct burn_drive_info *dinfo;
 struct burn_drive *drive;
 IsoImage *image= NULL;
 ElToritoBootImage *bootimg, **boots = NULL;
 IsoFile *bootimg_node, **bootnodes = NULL;
 IsoBoot *bootcat_node;

 Xorriso_alloc_meM(path, char, SfileadrL);
 Xorriso_alloc_meM(lb0, unsigned char, 2048);

 respt= xorriso->result_line;

 if(xorriso->boot_count > 0) {
   if(!(flag & 1)) {
     sprintf(respt, "Boot record  : (overridden by -boot_image any next)\n");
     Xorriso_toc_line(xorriso, flag & 8);
   }
   ret= 1; goto ex;
 }

 ret= Xorriso_get_drive_handles(xorriso, &dinfo, &drive,
                                "on attempt to print boot info", 16);
 if(ret<=0)
   goto no_boot;
 image= isoburn_get_attached_image(drive);
 if(image == NULL) {
   ret= 0;
no_boot:;
   if(!(flag & 1)) {
     sprintf(respt, "Boot record  : none\n");
     Xorriso_toc_line(xorriso, flag & 8);
   }
   goto ex;
 }

 ret= iso_image_report_system_area(image, &sa_report, &sa_count, 0);
 if(ret > 0 && sa_report != NULL)
   for(i= 0; i < sa_count; i++)
     if(strncmp(sa_report[i], "System area summary: ", 21) == 0) {
       Xorriso_alloc_meM(sa_summary, char, strlen(sa_report[i] + 21) + 1);
       strcpy(sa_summary, sa_report[i] + 21);
   break;
     }
 if(sa_report != NULL)
   iso_image_report_system_area(image, &sa_report, &sa_count, 1 << 15);
 Xorriso_process_msg_queues(xorriso,0);

 /* Using the nodes with extreme care . They might be deleted meanwhile. */
 ret= iso_image_get_boot_image(image, &bootimg, &bootimg_node, &bootcat_node);
 if(ret != 1) {
   if(sa_summary == NULL)
     goto no_boot;
   sprintf(respt, "Boot record  : (system area only) , %s\n", sa_summary);
   Xorriso_toc_line(xorriso, flag & 8);
   ret= 1; goto ex;
 }
 ret= iso_image_get_all_boot_imgs(image, &num_boots, &boots, &bootnodes, 0);
 Xorriso_process_msg_queues(xorriso,0);
 if(ret != 1) {
   num_boots= 0;
 } else {
   ret= Xorriso_path_from_node(xorriso, (IsoNode *) bootnodes[0], path, 0);
   if(ret > 0)
     bin_path_valid= 1;
 }
 sprintf(respt, "Boot record  : El Torito");
 if(sa_summary != NULL)
   sprintf(respt + strlen(respt), " , %s", sa_summary);

 strcat(respt, "\n");
 Xorriso_toc_line(xorriso, flag & 8);
 if(flag & 2)
   {ret= 1; goto ex;}

 if(xorriso->loaded_boot_cat_path[0]) {
   sprintf(respt, "Boot catalog : ");
   Text_shellsafe(xorriso->loaded_boot_cat_path, respt, 1);
   strcat(respt, "\n");
 } else {
   sprintf(respt, "Boot catalog : -not-found-at-load-time-\n");
 }
 Xorriso_toc_line(xorriso, flag & 8);

 if(bin_path_valid) {
   sprintf(respt, "Boot image   : ");
   Text_shellsafe(path, respt, 1);
 } else if(xorriso->loaded_boot_bin_lba <= 0) {
   sprintf(respt, "Boot image   : -not-found-at-load-time-");
 } else {
   sprintf(respt, "Boot image   : -not-found-any-more-by-lba=%d",
           xorriso->loaded_boot_bin_lba);
 }
 Xorriso__append_boot_params(respt, bootimg, 0);
 strcat(respt, "\n");
 Xorriso_toc_line(xorriso, flag & 8);

 if(num_boots > 1) {
   for(i= 1; i < num_boots; i++) {
     ret= Xorriso_path_from_node(xorriso, (IsoNode *) bootnodes[i], path, 0);
     if(ret > 0) {
       sprintf(respt, "Boot image   : ");
       Text_shellsafe(path, respt, 1);
     } else
       sprintf(respt, "Boot image   : -not-found-any-more-");
     Xorriso__append_boot_params(respt, boots[i], 0);
     strcat(respt, "\n");
     Xorriso_toc_line(xorriso, flag & 8);
   }
 }
 ret= 1;
ex:;
 if(boots != NULL)
   free(boots);
 if(bootnodes != NULL)
   free(bootnodes);
 if(image != NULL)
   iso_image_unref(image); /* release obtained reference */
 Xorriso_free_meM(path);
 Xorriso_free_meM(lb0);
 Xorriso_free_meM(sa_summary);
 return(ret);
} 


/* @param flag    bit0=silently return 0 if no volume/image is present
*/
int Xorriso_get_volume(struct XorrisO *xorriso, IsoImage **volume,
                       int flag)
{
 *volume= NULL;
 if(xorriso->in_volset_handle==NULL) {
   if(flag & 1)
     return(0);
   Xorriso_process_msg_queues(xorriso,0);
   sprintf(xorriso->info_text,"No ISO image present.");
   if(xorriso->indev[0]==0 && xorriso->outdev[0]==0)
     sprintf(xorriso->info_text+strlen(xorriso->info_text),
             " No -dev, -indev, or -outdev selected.");
   else
     sprintf(xorriso->info_text+strlen(xorriso->info_text),
             " Possible program error with drive '%s'.", xorriso->indev);

   if(!xorriso->no_volset_present)
     Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "FAILURE", 0);
   xorriso->no_volset_present= 1;
   return(0);
 }
 *volume= (IsoImage *) xorriso->in_volset_handle;
 xorriso->no_volset_present= 0;
 return(*volume != NULL);
}


/* @param flag bit0= do not return 1 on volset_change_pending != 1
*/
int Xorriso_change_is_pending(struct XorrisO *xorriso, int flag)
{
 if(flag & 1)
   return(xorriso->volset_change_pending == 1);
 return(!!xorriso->volset_change_pending);
}


/* @param flag bit0= do not set hln_change_pending */
int Xorriso_set_change_pending(struct XorrisO *xorriso, int flag)
{
 int ret;
 IsoImage *image;

 ret= Xorriso_get_volume(xorriso, &image, 1);
 if(ret <= 0)
   return ret;
 /* Do not override mark of -as mkisofs -print-size */
 if(xorriso->volset_change_pending != 2)
    xorriso->volset_change_pending= 1;
 if(!(flag & 1))
   xorriso->hln_change_pending= 1;
 return(1);
}


/**
    @param flag bit0= print mount command to result channel rather than
                      performing it 
                bit1= do not allow prefixes with cmd
                bit2= interpret unprefixed cmd as shell:
*/
int Xorriso_mount(struct XorrisO *xorriso, char *dev, int adr_mode,
                  char *adr_value, char *cmd, int flag)
{
 int ret, lba, track, session, params_flag= 0, is_safe= 0, is_extra_drive= 0;
 int give_up= 0, mount_chardev= 0, status, aquire_flag= 0;
 char volid[33], *devadr, *mount_command= NULL, *adr_data= NULL, *adr_pt;
 char *dev_path, *libburn_adr= NULL;
 char *dpt, *sysname= "";
 struct stat stbuf;
 struct burn_drive_info *dinfo= NULL;
 struct burn_drive *drive= NULL;

 Xorriso_alloc_meM(mount_command, char, SfileadrL);
 Xorriso_alloc_meM(adr_data, char, 163);
 Xorriso_alloc_meM(libburn_adr, char, BURN_DRIVE_ADR_LEN + SfileadrL);

 devadr= dev;
 adr_pt= adr_value;
 if(strcmp(dev, "indev") == 0) {
   ret= Xorriso_get_drive_handles(xorriso, &dinfo, &drive,
                                  "on attempt to perform -mount \"indev\"", 0);
   if(ret<=0)
     goto ex;
   dev_path= devadr= xorriso->indev;
   if(strncmp(dev_path, "stdio:", 6) == 0)
     dev_path+= 6;
   else if(strncmp(dev_path, "mmc:", 4) == 0)
     dev_path+= 4;
   if(xorriso->in_drive_handle == xorriso->out_drive_handle)
     give_up= 3;
   else
     give_up= 1;
 } else if(strcmp(dev, "outdev") == 0) {
   ret= Xorriso_get_drive_handles(xorriso, &dinfo, &drive,
                                  "on attempt to perform -mount \"outdev\"", 
                                  2);
   if(ret<=0)
     goto ex;
   dev_path= devadr= xorriso->outdev;
   if(strncmp(dev_path, "stdio:", 6) == 0)
     dev_path+= 6;
   else if(strncmp(dev_path, "mmc:", 4) == 0)
     dev_path+= 4;
   if(xorriso->in_drive_handle == xorriso->out_drive_handle)
     give_up= 3;
   else
     give_up= 2;
 } else {
   is_extra_drive= 1;
   dev_path= dev;
   if(strncmp(dev_path, "stdio:", 6) == 0)
     dev_path+= 6;
   else if(strncmp(dev_path, "mmc:", 4) == 0)
     dev_path+= 4;

   /* do only accept regular files and block devices */
   ret= stat(dev_path, &stbuf);
   if(ret == -1) {
     sprintf(xorriso->info_text, "Cannot determine properties of file ");
     Text_shellsafe(dev_path, xorriso->info_text, 1);
     Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "FAILURE", 0);
     ret= 0; goto ex;
   }
   ret= System_uname(&sysname, NULL, NULL, NULL, 0);
   if(ret > 0 && strcmp(sysname, "FreeBSD") == 0)
     mount_chardev= 1;
   if(!(S_ISREG(stbuf.st_mode) || (S_ISBLK(stbuf.st_mode) && !mount_chardev)
        || (S_ISCHR(stbuf.st_mode) && !mount_chardev))) {
     sprintf(xorriso->info_text,
             "File object is not suitable as mount device: ");
     Text_shellsafe(dev_path, xorriso->info_text, 1);
     Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "FAILURE", 0);
     ret= 0; goto ex;
   }

   /* Aquire drive as direct libburn address or via stdio: prefix */
   if(strncmp(dev, "mmc:", 4) == 0)
     ret= burn_drive_convert_fs_adr(dev + 4, libburn_adr);
   else
     ret= burn_drive_convert_fs_adr(dev, libburn_adr);
   Xorriso_process_msg_queues(xorriso,0);
   if(ret < 0)
     {ret= -1; goto ex;}
   if(ret == 0 && strncmp(dev, "stdio:", 6) != 0 &&
      strncmp(dev, "mmc:", 4) != 0)
     sprintf(libburn_adr, "stdio:%s", dev);
   burn_preset_device_open(
           (xorriso->drives_exclusive && !(xorriso->mount_opts_flag & 1)) |
           (xorriso->linux_scsi_dev_family << 2), 0, 0);
   aquire_flag= 1;
   if((xorriso->toc_emulation_flag & 2) && adr_mode == 3)
     aquire_flag|= 16;
   if(xorriso->toc_emulation_flag & 4)
     aquire_flag|= 128;
   if(xorriso->toc_emulation_flag & 8)
     aquire_flag|= 512;
   ret= isoburn_drive_aquire(&dinfo, libburn_adr, aquire_flag);
   burn_preset_device_open(1 | (xorriso->linux_scsi_dev_family << 2), 0, 0);
   Xorriso_process_msg_queues(xorriso,0);
   if(ret <= 0)
     {ret= 0; goto ex;}
   drive= dinfo[0].drive;
 }

 if(adr_mode == 4 && strlen(adr_pt) <= 80) {
   ret= Xorriso__bourne_to_reg(adr_pt, adr_data, 0);
   if(ret == 1) {
     params_flag|= 4;
     adr_pt= adr_data;
   }
 }
 ret= isoburn_get_mount_params(drive, adr_mode, adr_pt, &lba, &track,
                               &session, volid, params_flag);
 Xorriso_process_msg_queues(xorriso,0);
 if(ret <= 0)
   goto ex;
 if(((session <= 0 || track <= 0) && !(aquire_flag & 16)) || ret == 2) {
   Xorriso_msgs_submit(xorriso, 0,
                "-mount : Given address does not point to an ISO 9660 session",
                0, "FAILURE", 0);
   ret= 0; goto ex;
 }
 if(strstr(devadr, "stdio:") == devadr)
   devadr+= 6;
 if(strstr(devadr, "mmc:") == devadr)
   devadr+= 4;
 ret= Xorriso_make_mount_cmd(xorriso, cmd, lba, track, session, volid, devadr,
                          mount_command, (flag & (2 | 4)) | ((flag & 4) << 1));
 if(ret <= 0)
   goto ex;
 if(ret == 2)
   is_safe= 1;

 if(is_extra_drive) {
   isoburn_drive_release(drive, 0);
   burn_drive_info_free(dinfo);
   drive= NULL;
 } else if(give_up > 0 && !((flag & 1) || (xorriso->mount_opts_flag & 1))) {
   ret= Xorriso_give_up_drive(xorriso, give_up);
   if(ret <= 0)
     goto ex;
 }
 Xorriso_process_msg_queues(xorriso,0);

 sprintf(xorriso->info_text, "Volume id    : ");
 Text_shellsafe(volid, xorriso->info_text, 1);
 strcat(xorriso->info_text, "\n");
 Xorriso_info(xorriso, 0);
 if(flag & 1) {
   sprintf(xorriso->result_line, "%s\n", mount_command);
   Xorriso_result(xorriso,0);
 } else {
   sprintf(xorriso->info_text, "Mount command: %s\n", mount_command);
   Xorriso_info(xorriso, 0);
   if(!is_safe) {
     Xorriso_msgs_submit(xorriso, 0,
  "-mount : Will not perform mount command which stems from command template.",
       0, "SORRY", 0);
     sprintf(xorriso->result_line, "%s\n", mount_command);
     Xorriso_result(xorriso,0);
   } else {
     ret= Xorriso_execv(xorriso, mount_command, 0, NULL, "/bin:/sbin",
                        NULL, NULL, NULL, &status, 1);
     if(WIFEXITED(status) && WEXITSTATUS(status) != 0) {
       sprintf(xorriso->info_text,
               "-mount : mount command failed with exit value %d",
               (int) WEXITSTATUS(status));
       Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "FAILURE", 0);
       ret= 0; goto ex;
     }
     sprintf(xorriso->info_text, "\nMounted session %d of device ", session);
     Text_shellsafe(dev_path, xorriso->info_text, 1);
     dpt= strchr(cmd, ':');
     if(dpt == NULL)
       dpt= cmd ;
     else
       dpt++;
     sprintf(xorriso->info_text + strlen(xorriso->info_text), " as directory ");
     Text_shellsafe(dpt, xorriso->info_text, 1);
     strcat(xorriso->info_text, "\n");
     Xorriso_info(xorriso, 0);
   }
 }
 ret= 1;
ex:;
 if(is_extra_drive && drive != NULL) {
   isoburn_drive_release(drive, 0);
   burn_drive_info_free(dinfo);
   Xorriso_process_msg_queues(xorriso,0);
 }
 Xorriso_free_meM(mount_command);
 Xorriso_free_meM(adr_data);
 Xorriso_free_meM(libburn_adr);
 return(ret);
}


/* @param flag bit0= give up all boot file paths
               bit1= refuse if already a path is added
*/
int Xorriso_add_mips_boot_file(struct XorrisO *xorriso, char *path, int flag)
{
 int ret;
 IsoImage *image;
 char *paths[15];

 ret= Xorriso_get_volume(xorriso, &image, 0);
 if(ret <= 0)
   return ret;
 if(flag & 1) {
   iso_image_give_up_mips_boot(image, 0);
   Xorriso_process_msg_queues(xorriso,0);
   return(1);
 }
 if(flag & 2) {
   ret= iso_image_get_mips_boot_files(image, paths, 0);
   Xorriso_process_msg_queues(xorriso,0);
   if(ret < 0)
     goto report_error;
   if(ret > 0) {
     Xorriso_msgs_submit(xorriso, 0,
                         "There is already a boot image file registered.",
                         0, "FAILURE", 0);
     return(0);
   }
 }
 ret = iso_image_add_mips_boot_file(image, path, 0);
 Xorriso_process_msg_queues(xorriso,0);
 if (ret < 0) {
report_error:;
   Xorriso_report_iso_error(xorriso, "", ret,
                            "Error when adding MIPS boot file",
                            0, "FAILURE", 1);
   return(0);
 }
 return(1);
}


/* @param flag bit0= Give up HP-PA boot parameters
*/
int Xorriso_set_hppa_boot_parm(struct XorrisO *xorriso, char *text, char *what,
                               int flag)
{
 int ret;
 IsoImage *image;
 char *par[5];

 ret= Xorriso_get_volume(xorriso, &image, 0);
 if(ret <= 0)
   return(ret);
 par[0]= par[1]= par[2]= par[3]= par[4]= NULL;
 if(flag & 1) {
   /* Give up HP-PA boot parameters */
   iso_image_set_hppa_palo(image, par[0], par[1], par[2], par[3], par[4],
                           1);
   return(1);
 }
 if(strcmp(what, "cmdline") == 0) {
   par[0]= text;
 } else if(strcmp(what, "bootloader") == 0) {
   par[1]= text;
 } else if(strcmp(what, "kernel_32") == 0 || strcmp(what, "kernel-32") == 0) {
   par[2]= text;
 } else if(strcmp(what, "kernel_64") == 0 || strcmp(what, "kernel-64") == 0) {
   par[3]= text;
 } else if(strcmp(what, "ramdisk") == 0) {
   par[4]= text;
 } else if(strcmp(what, "hdrversion") == 0) {
   if(strcmp(text, "4") == 0) {
     xorriso->system_area_options= (xorriso->system_area_options & ~0xfc) |
                                   (4 << 2);
   } else if(strcmp(text, "5") == 0) {
     xorriso->system_area_options= (xorriso->system_area_options & ~0xfc) |
                                   (5 << 2);
   } else {
     strcpy(xorriso->info_text, "Unsupported HP-PA PALO header version ");
     Text_shellsafe(text, xorriso->info_text, 1);
     Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "FAILURE", 0);
     return(0);
   }
   return(1);
 } else {
   strcpy(xorriso->info_text,
          "HP-PA boot parameter name not recognized: hppa_");
   Text_shellsafe(what, xorriso->info_text, 1);
   Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "FAILURE", 0);
   return(0);
 }
 ret= iso_image_set_hppa_palo(image, par[0], par[1], par[2], par[3], par[4],
                              0);
 if (ret < 0) {
   Xorriso_report_iso_error(xorriso, "", ret,
                            "Error when adding HP-PA boot parameter",
                            0, "FAILURE", 1);
   return(0);
 }
 return(1);
}


/* @param flag bit0= Give up DEC Alpha boot parameters
*/
int Xorriso_set_alpha_boot(struct XorrisO *xorriso, char *path, int flag)
{
 int ret;
 IsoImage *image;

 ret= Xorriso_get_volume(xorriso, &image, 0);
 if(ret <= 0)
   return(ret);
 if(flag & 1) {
   /* Give up boot parameters */
   iso_image_set_alpha_boot(image, NULL, 1);
   return(1);
 }
 ret= iso_image_set_alpha_boot(image, path, 0);
 if (ret < 0) {
   Xorriso_report_iso_error(xorriso, "", ret,
                            "Error when adding DEC Alpha boot loader",
                            0, "FAILURE", 1);
   return(0);
 }
 return(1);
}
 

/* @param flag bit0= do not set xorriso->system_area_options, just check
               bit1= only check for grub2_mbr <-> isolinux partition_table
*/
int Xorriso_coordinate_system_area(struct XorrisO *xorriso, int sa_type,
                                   int options, char *cmd, int flag)
{
 int old_type, old_options, new_options;
 static char *type_names[7] = {
      "MBR", "MIPS Big Endian Volume Header", "MIPS Little Endian Boot Block",
      "SUN Disk Label", "HP-PA PALO v4", "HP-PA PALO v5",
      "DEC Alpha SRM Boot Block"};
 static int num_names = 7;

 old_type= (xorriso->system_area_options & 0xfc) >> 2;
 old_options= xorriso->system_area_options & 0x3c03;
 new_options= options & 0x3c03;
 if(((options & (1 << 14)) && (xorriso->system_area_options & 2)) ||
    ((options & 2) && (xorriso->system_area_options & (1 << 14))))
   goto reject;
 if(flag & 2)
   return(1);
 if((old_type != 0 || old_options != 0) &&
    (old_type != sa_type || (old_options != 0 && old_options != new_options))){
reject:;
   sprintf(xorriso->info_text, "%s : First sector already occupied by %s",
           cmd, old_type < num_names ?
                type_names[old_type] : "other boot facility");
   if(old_type == 0 && (old_options & 2))
     strcat(xorriso->info_text, " for ISOLINUX isohybrid");
   else if (old_type == 0 && (xorriso->system_area_options & (1 << 14))) {
     strcat(xorriso->info_text, " for GRUB2 patching");
     if(old_type == 0 && (old_options & 1))
       strcat(xorriso->info_text, " with partition table");
   } else if(old_type == 0 && (old_options & 1))
     strcat(xorriso->info_text, " for partition table");
   Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "FAILURE", 0);
   goto hint_revoke;
 }
 if(!(flag & 1))
   xorriso->system_area_options= (xorriso->system_area_options & ~0x3cff) |
                                 ((sa_type << 2) & 0xfc) | (options & 0x3c03);
 return(1);

hint_revoke:;
 if(old_type == 0)
   sprintf(xorriso->info_text, "Revokable by -boot_image any discard");
 else if(old_type == 1 || old_type == 2)
   sprintf(xorriso->info_text, "Revokable by -boot_image any mips_discard");
 else if(old_type == 3)
   sprintf(xorriso->info_text, "Revokable by -boot_image any sparc_discard");
 if(old_type < 4)
   Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "HINT", 0);
 return(0);
}


int Xorriso_gpt_crc(struct XorrisO *xorriso, char *path, int flag)
{
 int ret;
 char *buf = NULL;
 FILE *fp = NULL;
 uint32_t crc;

 Xorriso_alloc_meM(buf, char, 32 * 1024);

 ret= Xorriso_afile_fopen(xorriso, path, "rb", &fp, 0);
 if(ret <= 0)
   goto ex;
 ret= fread(buf, 1, 32 * 1024, fp);
 if(ret == 0) {
   strcpy(xorriso->info_text,
          "No bytes readable for GPT CRC from ");
   Text_shellsafe(path, xorriso->info_text, 1);
   Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "WARNING", 0);
   ret= 0; goto ex;
 }
 crc= iso_crc32_gpt((unsigned char *) buf, ret, 0);
 sprintf(xorriso->result_line, "0x%8.8x\n", (unsigned int) crc);
 Xorriso_result(xorriso, 0);
 ret= 1;
ex:;
 if(fp != NULL && fp != stdin)
   fclose(fp);
 Xorriso_free_meM(buf);
 return(ret);
}


static int Xorriso_split_report_line(struct XorrisO *xorriso, char *line,
                                     int num_limit,
                                     char *name, char **contentpt,
                                     double *num, int *num_count,
                                     char **textpt, int flag)
{
 int i;
 char *spt, *ept, *cpt;

 if(strlen(line) < 21) {
undigestible:
   sprintf(xorriso->info_text,
           "Undigestible report line with -report_* mode cmd: '%s'", line);
   Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "SORRY", 0);
   return(0);
 }
 if(line[19] != ':')
   goto undigestible;
 strncpy(name, line, 20);
 name[20]= 0;

 for(spt= line + 20; *spt == ' '; spt++);
 *textpt= *contentpt= spt;
 *num_count= 0;
 for(i= 0; i < num_limit; i++) {
   /* Get word */
   for(spt= *textpt; *spt == ' '; spt++);
   if(*spt == 0) {
     *textpt= spt;
 break;
   }
   for(ept= spt + 1; *ept != ' ' && *ept != 0; ept++);
   /* Look for decimal number */
   if(ept - spt > 16)
 break;
   for(cpt= spt; cpt < ept; cpt++)
     if(*cpt < '0' || *cpt > '9')
   break;
   if(cpt != ept)
 break;
   sscanf(spt, "%lf", num + *num_count);
   (*num_count)++;
   *textpt= ept;
 }
 /* Set *textpt to next non-blank */
 for(; **textpt == ' '; (*textpt)++);
 return(1);
}


int Xorriso_record_cmd_line(struct XorrisO *xorriso, char *buf,
                            char **cmds, int *cmd_count, int flag)
{
 int ret;

 if(flag & 1) {
   (*cmd_count)++;
   ret= 1; goto ex;
 }
 Xorriso_alloc_meM(cmds[*cmd_count], char, strlen(buf) + 1);
 strcpy(cmds[*cmd_count], buf);
 (*cmd_count)++;
 ret= 1;
ex:;
 return(ret);
}


/* @param flag bit0= zeroize MBR partition table
               bit1= zeroize GPT
               bit2= zeroize APM
              bit30= Source imported_iso rather than local_fs
*/
int Xorriso_add_intvl_adr(struct XorrisO *xorriso, char *buf,
                          uint64_t start_adr, uint64_t end_adr, char *suffix,
                          int flag)
{
 char *path;

 sprintf(buf + strlen(buf), "--interval:%s:%.f%s-%.f%s:",
         ((flag & (1 << 30)) ? "imported_iso" : "local_fs"),
         (double) start_adr, suffix, (double) end_adr, suffix);
 if(flag & 1)
   strcat(buf, "zero_mbrpt,");
 if(flag & 2)
   strcat(buf, "zero_gpt,");
 if(flag & 4)
   strcat(buf, "zero_apm,");
 if(buf[strlen(buf) - 1] == ',')
   buf[strlen(buf) - 1] = 0;
 strcat(buf, ":");
 path= xorriso->indev;
 if(strncmp(path, "stdio:", 6) == 0)
   path+= 6;
 Text_shellsafe(path, buf, 1);
 return(1);
}


struct elto_img_par {
 int n, ldsiz, boot_info_table, grub2_boot_info;
 int do_gpt_basdat, do_gpt_hfsplus, do_apm_hfsplus;
 unsigned int ld_seg, hdpt, platform_id;
 unsigned long int lba;
 char pltf[8], b[8], emul[8], boot_image_type[16];
 char *path, *id_string, *sel_crit;
};


/* @param ptype   0= unknown, 1= gpt-basdat, 2=gpt-hfsplus, 3=EFI
   @param flag    bit0= isohybrid
*/
static int Xorriso_register_eltorito_gpt(struct XorrisO *xorriso,
                                         struct elto_img_par *et_img,
                                         int ptype,
                                         int *efi_boot_part, int *first_efi,
                                         int flag)
{
 if(flag & 1) {
   if(ptype == 1 || ptype == 3)
     et_img->do_gpt_basdat= 1;
   else if(ptype == 2)
     et_img->do_gpt_hfsplus= 1;
   return(1);
 } else if(*first_efi && et_img->platform_id == 0xef) {
   *efi_boot_part= 1;
   return(1);
 }
 if(et_img->platform_id == 0xef)
   *first_efi= 0;
 return(0);
}


/* @param ptype   0= unknown, 1= gpt-basdat, 2=gpt-hfsplus, 3=EFI
   @param flag    bit0= isohybrid
*/
static int Xorriso_search_eltorito_path(struct XorrisO *xorriso,
                                        struct elto_img_par *et_imgs,
                                        int elto_count, char *path, int ptype,
                                        int *found, int *efi_boot_part,
                                        int flag)
{
 int first_efi= 1, et_idx, ret;

 for(et_idx= 0; et_idx < elto_count; et_idx++) {
   if(strcmp(et_imgs[et_idx].path, path) != 0)
 continue;
   ret= Xorriso_register_eltorito_gpt(xorriso, et_imgs + et_idx,
                                      ptype, efi_boot_part, &first_efi, flag);
   if(ret > 0)
 break;
 }
 *found= et_idx;
 if(et_idx < elto_count)
   return(1);
 return(0);
}


static int Xorriso_search_eltorito_lba(struct XorrisO *xorriso,
                                       struct elto_img_par *et_imgs,
                                       int elto_count,
                                       unsigned int lba,
                                       int *found, int flag)
{
 int et_idx;

 for(et_idx= 0; et_idx < elto_count; et_idx++)
   if(et_imgs[et_idx].lba == lba)
 break;
 *found= et_idx;
 if(et_idx < elto_count)
   return(1);
 return(0);
}


int Xorriso_highest_data_block(struct XorrisO *xorriso, uint32_t *high_block,
                               int flag)
{
 int ret;
 struct FindjoB *job= NULL;
 struct stat dir_stbuf;

 *high_block= 0;
 ret= Findjob_new(&job, "/", 0);
 if(ret <= 0) {
   Xorriso_no_findjob(xorriso, "[internal:last_data_file_block]", 0);
   {ret= -1; goto ex;}
 }
 Findjob_set_action_type(job, 58, 0, 0);
 ret= Xorriso_findi(xorriso, job, NULL,  (off_t) 0,
                    NULL, "/", &dir_stbuf, 0, 0);
 if(ret <= 0)
   goto ex;
 Findjob_get_last_data_file_block(job, high_block, 0);
ex:;
 Findjob_destroy(&job, 0);
 return(ret);
}


/* @param flag bit0= do not record but only count
               bit1= as_mkisofs
*/
static int Xorriso_scan_report_lines(struct XorrisO *xorriso,
                                     char **et_lines, int et_line_count,
                                     char **sa_lines, int sa_line_count,
                                     char **cmds, int *cmd_count, int flag)
{
 int ret= 0, i, num_count, mkisofs, line_count, idx, et_idx, isohybrid= 0;
 int ptype, gpt_idx, j, pad, mbr_idx;
 int efi_boot_part= 0, full_sparc_part= 0, have_sparc_part= 0, fe_dummy= 1;
 int appended_as_gpt= 0, have_prep= 0, did_sysarea= 0, cared_for_apm= 0;
 int cared_for_sparc= 0, have_hfsplus= 0;
 int have_sysarea= 0, ptable_killer, imported_iso, have_alpha_ldr_path= 0;
 int have_protective_msdos= 0, part_like_isohybrid= 0;

#ifdef Not_any_more_because_padding_is_now_after_partitions
 int appended_partition= 0;
#endif

 int iso_mbr_part_type= -1;
 unsigned int prev_pltf= 0;
 unsigned long int sa_options= 0, partno, id_tag, perms, start_cyl, num_blocks;
 unsigned long int part_status, part_type, start_block, partition_offset= 0;
 uint32_t high_block= 0;
 char name[24], *textpt, *contentpt, *buf= NULL;
 char **lines= NULL;
 double num[8];
 char *cat_path= "";
 struct elto_img_par *et_imgs= NULL;
 int elto_count= 0;
 uint32_t img_blocks= 0, mbr_parts_end= 0, iso_part_blocks;
 struct FindjoB *job= NULL;
 struct stat dir_stbuf;
 IsoImage *image;
 char *volid, *crt, *mdt, *ext, *eft, uuid[17], *uuid_time;
 char **app_pseudo_paths= NULL;
 struct tm tm_erg;
 int was_force_bootable= 0;
 uint64_t gpt_bheader_block= 0;

 struct mbr_par {
   uint8_t ptype;
   uint64_t start_block;
   uint64_t block_count;
   int appended;
   int has_path;
 };
 struct mbr_par *mbrpts= NULL;
 int mbr_count= 0;

 struct gpt_par {
   int ptype; /* 0= unknown, 1= gpt-basdat, 2=gpt-hfsplus, 3=EFI */
   int is_gap;
   int has_path;
   char *path;
   uint64_t start_block;
   uint64_t block_count;
 };
 struct gpt_par *gpts= NULL;
 int gpt_count= 0;

 struct apm_par {
   int ptype; /* bit0= type Apple_HFS , bit1= name HFSPLUS_Hybrid */
   char *path;
 };
 struct apm_par *apms= NULL; 
 int apm_count= 0;

#define Xorriso_record_cmd_linE { \
     ret= Xorriso_record_cmd_line(xorriso, buf, cmds, cmd_count, flag & 1); \
     if(ret <= 0) \
       goto ex; \
 }

 mkisofs= !!(flag & 2);
 imported_iso= (!mkisofs) << 30;

 *cmd_count= 0;
 line_count= et_line_count + sa_line_count;
 if(line_count <= 0)
   {ret= 1; goto ex;}

 Xorriso_alloc_meM(buf, char, 80 + SfileadrL);
 Xorriso_alloc_meM(lines, char *, line_count);
 for(i= 0; i < et_line_count; i++)
   lines[i]= et_lines[i];
 for(i= 0; i < sa_line_count; i++)
   lines[i + et_line_count]= sa_lines[i];

 /* Pre-scan to establish context */
 for(i= 0; i < line_count; i++) {
   ret= Xorriso_split_report_line(xorriso, lines[i], 8, name, &contentpt,
                                  num, &num_count, &textpt, 0);
   if(ret <= 0)
     goto ex;
   if(strcmp(name, "System area options:") == 0) {
     sscanf(contentpt, "%lx", &sa_options);

   } else if(strcmp(name, "System area summary:") == 0) {
     have_sysarea= 1;

   } else if(strcmp(name, "El Torito boot img :") == 0) {
     if(num[0] > elto_count)
       elto_count= num[0];

   } else if(strcmp(name, "PReP boot partition:") == 0) {
     have_prep= 1;

   } else if(strcmp(name, "MBR partition      :") == 0) {
     if(num[0] > mbr_count)
       mbr_count= num[0];

   } else if(strcmp(name, "GPT partition name :") == 0) {
     if(num[0] > gpt_count)
       gpt_count= num[0];

   } else if(strcmp(name, "APM partition name :") == 0) {
     if(num[0] > apm_count)
       apm_count= num[0];

   } else if(strcmp(name, "ISO image size/512 :") == 0) {
     img_blocks= num[0];

   } else if(strcmp(name, "Partition offset   :") == 0 &&
      (num[0] == 0 || num[0] == 16)) {
     partition_offset= num[0];

   }
 }

 ret= Xorriso_highest_data_block(xorriso, &high_block, 0);
 if(ret < 0)
   goto ex;
 if(ret == 0)
   high_block = img_blocks - 1;

 if(elto_count > 0) {
   Xorriso_alloc_meM(et_imgs, struct elto_img_par, elto_count);
   for(et_idx= 0; et_idx < elto_count; et_idx++) {
     et_imgs[et_idx].path= NULL;
     et_imgs[et_idx].ldsiz= -1;
   }
   Xorriso_alloc_meM(app_pseudo_paths, char *, elto_count);
   for(i= 0; i < elto_count; i++)
     app_pseudo_paths[i]= NULL;
   for(i= 0; i < elto_count; i++) {
     Xorriso_alloc_meM(app_pseudo_paths[i], char, 80);
     app_pseudo_paths[i][0]= 0;
   }
 }
 if(mbr_count > 0)
   Xorriso_alloc_meM(mbrpts, struct mbr_par, mbr_count);
 if(gpt_count > 0) {
   Xorriso_alloc_meM(gpts, struct gpt_par, gpt_count);
   for(gpt_idx= 0; gpt_idx < gpt_count; gpt_idx++)
     gpts[gpt_idx].path= NULL;
 }
 if(apm_count > 0) {
   Xorriso_alloc_meM(apms, struct apm_par, apm_count);
   for(i= 0; i < apm_count; i++)
     apms[i].path= NULL;
 }

 ptable_killer= (mbr_count > 0) | ((gpt_count > 0) << 1) |
                ((apm_count > 0) << 2);

 /* Report volume id and GRUB2 modification date */;
 ret= Xorriso_get_volume(xorriso, &image, 0);
 if(ret <= 0)
   goto ex;
 if(mkisofs)
   sprintf(buf, "-V ");
 else
   sprintf(buf, "-volid ");
 volid= (char *) un0(iso_image_get_volume_id(image));
 Text_shellsafe(volid, buf, 1);
 Xorriso_record_cmd_linE
 ret= iso_image_get_pvd_times(image, &crt, &mdt, &ext, &eft);
 if(ret == ISO_SUCCESS) {
   uuid_time= crt;
   /* If Creation Time is bad and Modification Time is ok: use the latter */
   ret= Decode_ecma119_format(&tm_erg, crt, 0);
   if(ret <= 0 || strlen(crt) != 16) {
     ret= Decode_ecma119_format(&tm_erg, mdt, 0);
     if(!(ret <= 0 || strlen(mdt) != 16))
       uuid_time= mdt;
   }
   pad= 0;
   for(j= 0; j < 16; j++) {
     if(pad) {
       uuid[j]= '0';
     } else if(uuid_time[j] == 0) {
       pad= 1;
       uuid[j]= '0';
     } else if(uuid_time[j] < '0' || uuid_time[j] > '9') {
       uuid[j]= '0';
     } else {
       uuid[j]= uuid_time[j];
     }
   }
   uuid[16]= 0;
   ret= Decode_ecma119_format(&tm_erg, uuid, 0);
   if(!(ret <= 0 || strlen(uuid) != 16)) {
     if(mkisofs)
       sprintf(buf, "--modification-date=");
     else
       sprintf(buf, "-volume_date uuid ");
     Text_shellsafe(uuid, buf, 1);
     Xorriso_record_cmd_linE
   }
 }

 /* First pass: set up objects, record El Torito and info needed in 2nd pass */
 for(i= 0; i < line_count; i++) {
   buf[0]= 0;
   ret= Xorriso_split_report_line(xorriso, lines[i], 8, name, &contentpt,
                                  num, &num_count, &textpt, 0);
   if(ret <= 0)
     goto ex;

   if(strcmp(name, "El Torito cat path :") == 0) {
     cat_path= textpt;

   } else if(strcmp(name, "El Torito boot img :") == 0) {
     /* Platform Id, bootability, emulation, load segment,
        Hard disk emulation partition type, Load size
     */
     idx= num[0] - 1;
     sscanf(contentpt, "%d %s %s %s %x %x %d %lu",
            &(et_imgs[idx].n), et_imgs[idx].pltf, et_imgs[idx].b,
            et_imgs[idx].emul, &(et_imgs[idx].ld_seg), &(et_imgs[idx].hdpt),
            &(et_imgs[idx].ldsiz), &(et_imgs[idx].lba));
     if(strcmp(et_imgs[idx].pltf, "BIOS") == 0)
       et_imgs[idx].platform_id= 0;
     else if(strcmp(et_imgs[idx].pltf, "PPC") == 0)
       et_imgs[idx].platform_id= 1;
     else if(strcmp(et_imgs[idx].pltf, "Mac") == 0)
       et_imgs[idx].platform_id= 2;
     else if(strcmp(et_imgs[idx].pltf, "UEFI") == 0)
       et_imgs[idx].platform_id= 0xef;
     else
       sscanf(et_imgs[idx].pltf, "%x", &(et_imgs[idx].platform_id));

     strcpy(et_imgs[idx].boot_image_type, "any");
     et_imgs[idx].boot_info_table= 0;
     et_imgs[idx].grub2_boot_info= 0;
     et_imgs[idx].path= et_imgs[idx].id_string= et_imgs[idx].sel_crit= "";
     et_imgs[idx].do_gpt_basdat= et_imgs[idx].do_gpt_hfsplus= 0;
     et_imgs[idx].do_apm_hfsplus= 0;

   } else if(strcmp(name, "El Torito img path :") == 0) {
     idx= num[0] - 1;
     et_imgs[idx].path= textpt;

   } else if(strcmp(name, "El Torito img opts :") == 0) {
     idx= num[0] - 1;
     if(strstr(textpt, "boot-info-table") != NULL)
       et_imgs[idx].boot_info_table= 1;
     if(strstr(textpt, "isohybrid-suitable") != NULL)
       strcpy(et_imgs[idx].boot_image_type, "isolinux");
     if(strstr(textpt, "grub2-boot-info") != NULL) {
       strcpy(et_imgs[idx].boot_image_type, "grub");
       et_imgs[idx].grub2_boot_info= 1;
     }

   } else if(strcmp(name, "El Torito id string:") == 0) {
     idx= num[0] - 1;
     et_imgs[idx].id_string= textpt;

   } else if(strcmp(name, "El Torito sel crit :") == 0) {
     idx= num[0] - 1;
     et_imgs[idx].sel_crit= textpt;

   } else if(strcmp(name, "System area summary:") == 0) {
     if(strstr(textpt, "protective-msdos-label") != NULL)
       have_protective_msdos= 1;

   } else if(strcmp(name, "MBR partition      :") == 0) {
     sscanf(contentpt, "%lu 0x%lx 0x%lx %lu %lu",
            &partno, &part_status, &part_type, &start_block, &num_blocks);
     idx= partno - 1;
     mbrpts[idx].ptype= part_type;
     mbrpts[idx].start_block= start_block;
     mbrpts[idx].block_count= num_blocks;
     if(num_blocks > 0 && start_block + num_blocks > mbr_parts_end)
       mbr_parts_end= start_block + num_blocks; 
     if(start_block == partition_offset * 4 &&
        (start_block + num_blocks) >= high_block * 4 && iso_mbr_part_type < 0)
       iso_mbr_part_type = part_type;

   } else if(strcmp(name, "MBR partition path :") == 0) {
     idx= num[0] - 1;
     mbrpts[idx].has_path= 1;

   } else if(strcmp(name, "GPT lba range      :") == 0) {
     gpt_bheader_block= num[2];

   } else if(strcmp(name, "GPT type GUID      :") == 0) {
     idx= num[0] - 1;
     if(strcmp(textpt, "a2a0d0ebe5b9334487c068b6b72699c7") == 0)
       gpts[idx].ptype= 1; /* Basic data */
     else if(strcmp(textpt, "005346480000aa11aa1100306543ecac") == 0)
       gpts[idx].ptype= 2; /* HFS+ */
     else if(strcmp(textpt, "28732ac11ff8d211ba4b00a0c93ec93b") == 0)
       gpts[idx].ptype= 3; /* EFI System Partition */
     else
       gpts[idx].ptype= 0;

   } else if(strcmp(name, "GPT start and size :") == 0) {
     idx= num[0] - 1;
     if(num[2] > 0)
       appended_as_gpt= 1;
     gpts[idx].start_block= num[1];
     gpts[idx].block_count= num[2];

   } else if(strcmp(name, "GPT partition path :") == 0) {
     idx= num[0] - 1;
     gpts[idx].has_path= 1;
     gpts[idx].path= textpt;

   } else if(strcmp(name, "GPT partition name :") == 0) {
     idx= num[0] - 1;
     if(strstr(contentpt, " 470061007000") != NULL) /* "Gap"... */
       gpts[idx].is_gap= 1;

   } else if(strcmp(name, "APM partition name :") == 0) {
     idx= num[0] - 1;
     if(strcmp(textpt, "HFSPLUS_Hybrid") == 0)
       apms[idx].ptype|= 2;

   } else if(strcmp(name, "APM partition type :") == 0) {
     idx= num[0] - 1;
     if(strcmp(textpt, "Apple_HFS") == 0)
       apms[idx].ptype|= 1;

   } else if(strcmp(name, "APM partition path :") == 0) {
     idx= num[0] - 1;
     apms[idx].path= textpt;

   } else if(strcmp(name, "DEC Alpha ldr path :") == 0) {
     have_alpha_ldr_path= 1;

   }
 }

 if(appended_as_gpt && !have_protective_msdos) {
   if(mbr_count != 1) {
     appended_as_gpt= 0;
   } else if(mbrpts[0].ptype != 0xee || mbrpts[0].start_block != 1) {
     appended_as_gpt= 0;
   } else if(gpt_bheader_block != mbrpts[0].block_count) {
     appended_as_gpt= 0;
   }
 }

 iso_part_blocks= img_blocks;
 for(mbr_idx = 0; mbr_idx < mbr_count; mbr_idx++) {
   if(mbrpts[mbr_idx].start_block == partition_offset * 4) {
     iso_part_blocks= mbrpts[mbr_idx].block_count + partition_offset * 4;
 break;
   }
 }

 /* Second pass: scan for System Area info */
 for(i= 0; i < line_count; i++) {
   buf[0]= 0;
   ret= Xorriso_split_report_line(xorriso, lines[i], 8, name, &contentpt,
                                  num, &num_count, &textpt, 0);
   if(ret <= 0)
     goto ex;

   if(strcmp(name, "System area options:") == 0) {
     if((sa_options & 0x3c00) == 0x0400) {
       if(mkisofs)
         sprintf(buf, "-chrp-boot-part ");
       else
         sprintf(buf, "-boot_image any chrp_boot_part=on ");
     }

   } else if(strcmp(name, "System area summary:") == 0) {
     if(strstr(textpt, "isohybrid") != NULL) {
       isohybrid= 1;
       if(mkisofs)
         sprintf(buf, "-isohybrid-mbr ");
       else
         sprintf(buf, "-boot_image isolinux system_area=");
       Xorriso_add_intvl_adr(xorriso, buf, (uint64_t) 0, (uint64_t) 15, "s",
                             imported_iso | ptable_killer);
       Xorriso_record_cmd_linE
       did_sysarea= 1;
     }
     if(strstr(textpt, "grub2-mbr") != NULL) {
       if(mkisofs)
         sprintf(buf, "--grub2-mbr ");
       else
         sprintf(buf, "-boot_image grub grub2_mbr=");
       Xorriso_add_intvl_adr(xorriso, buf, (uint64_t) 0, (uint64_t) 15, "s",
                             imported_iso | ptable_killer);
       Xorriso_record_cmd_linE
       did_sysarea= 1;
     }
     if(strstr(textpt, "protective-msdos-label") != NULL) {
       if(mkisofs)
         sprintf(buf, "--protective-msdos-label");
       else
         sprintf(buf, "-boot_image any partition_table=on");
       Xorriso_record_cmd_linE
     }
     if(strstr(textpt, "cyl-align-off") != NULL) {
       if(mkisofs)
         sprintf(buf, "-partition_cyl_align off");
       else
         sprintf(buf, "-boot_image any partition_cyl_align=off");
     } else if(strstr(textpt, "cyl-align-all") != NULL) {
       if(mkisofs)
         sprintf(buf, "-partition_cyl_align all");
       else
         sprintf(buf, "-boot_image any partition_cyl_align=all");
     } else if(strstr(textpt, "cyl-align-") != NULL) {
       if(mkisofs)
         sprintf(buf, "-partition_cyl_align on");
       else
         sprintf(buf, "-boot_image any partition_cyl_align=on");
     } else
       buf[0]= 0;

   } else if(strcmp(name, "Partition offset   :") == 0 &&
      (num[0] == 0 || num[0] == 16)) {
     if(mkisofs)
       sprintf(buf, "-partition_offset %.f", num[0]);
     else
       sprintf(buf, "-boot_image any partition_offset=%.f", num[0]);

   } else if(strcmp(name, "MBR heads per cyl  :") == 0 &&
      (num[0] > 0 && num[0] <= 255)) {
     if(mkisofs)
       sprintf(buf, "-partition_hd_cyl %.f", num[0]);
     else
       sprintf(buf, "-boot_image any partition_hd_cyl=%.f", num[0]);

   } else if(strcmp(name, "MBR secs per head  :") == 0 &&
      (num[0] > 0 && num[0] <= 63)) {
     if(mkisofs)
       sprintf(buf, "-partition_sec_hd %.f", num[0]);
     else
       sprintf(buf, "-boot_image any partition_sec_hd=%.f", num[0]);

   } else if(strcmp(name, "MBR partition      :") == 0) {
     sscanf(contentpt, "%lu 0x%lx 0x%lx %lu %lu",
            &partno, &part_status, &part_type, &start_block, &num_blocks);
     if(num_blocks > 0 && part_type != 0x00 && part_type != 0xee &&
        (iso_part_blocks <= start_block ||
         (have_protective_msdos && img_blocks == mbr_parts_end &&
          partno > 1))) {
       if(!appended_as_gpt) {
         sprintf(buf, "-append_partition %lu 0x%lx ", partno, part_type);
         Xorriso_add_intvl_adr(xorriso, buf, (uint64_t) start_block,
                               ((uint64_t) start_block) + num_blocks - 1, "d",
                               imported_iso);
         if(partno >= 1 && (int) partno <= mbr_count)
           mbrpts[partno - 1].appended= 1;

#ifdef Not_any_more_because_padding_is_now_after_partitions
         appended_partition= 1;
#endif

       }
     } else if(part_type == 0x41 && have_prep) {
       if(mkisofs) {
         sprintf(buf, "-prep-boot-part ");
       } else {
         sprintf(buf, "-boot_image any prep_boot_part=");
       }
       Xorriso_add_intvl_adr(xorriso, buf, (uint64_t) start_block,
                             ((uint64_t) start_block) + num_blocks - 1, "d",
                             imported_iso);
     }
     if((part_status & 0x80) && !was_force_bootable) {
       was_force_bootable= 1;
       if(buf[0]) {
         Xorriso_record_cmd_linE
         buf[0]= 0;
       }
       if(mkisofs)
         sprintf(buf, "--mbr-force-bootable");
       else
         sprintf(buf, "-boot_image any mbr_force_bootable=on");
     }
   } else if(strcmp(name, "MBR partition path :") == 0) {
     idx= num[0] - 1;
     if(mbrpts[idx].ptype == 0x41) {
       sprintf(xorriso->info_text,
               "Cannot make proposal to mark PReP partition by data file: ");
       Text_shellsafe(textpt, xorriso->info_text, 1);
       if(!(flag & 1))
         Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "SORRY", 0);
 continue;
     }
     ptype= 0;
     if(mbrpts[idx].ptype == 0xef)
       ptype= 3;
     ret= Xorriso_search_eltorito_path(xorriso, et_imgs, elto_count,
                                       textpt, ptype,
                                       &et_idx, &efi_boot_part, !!isohybrid);
     if(ret <= 0) {
       sprintf(xorriso->info_text,
               "Cannot make proposal to mark data file as MBR partition without being an El Torito boot image : ");
       Text_shellsafe(textpt, xorriso->info_text, 1);
       if(!(flag & 1))
         Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "SORRY", 0);
     } else {
       for(gpt_idx= 0; gpt_idx < gpt_count; gpt_idx++) {
         if(gpts[gpt_idx].path != NULL)
           if(strcmp(gpts[gpt_idx].path, textpt) == 0)
       break;
       }
       if(gpt_idx >= gpt_count) {
         sprintf(xorriso->info_text,
                 "Cannot make proposal to mark data file as MBR partition without being in GPT : ");
         Text_shellsafe(textpt, xorriso->info_text, 1);
         if(!(flag & 1))
           Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "SORRY", 0);
       }
     } 

   } else if(strcmp(name, "GPT disk GUID      :") == 0) {

     /* >>> ??? need command to set disk GUID */;

   } else if(strcmp(name, "GPT partition name :") == 0) {

     /* >>> ??? need command to set partition name for partition number */;

   } else if(strcmp(name, "GPT partition GUID :") == 0) {

     /* >>> ??? need command to set partition GUID for partition number */;

   } else if(strcmp(name, "GPT partition flags:") == 0) {

     /* >>> check whether 0x1000000000000001 . Else: complain */;

   } else if(strcmp(name, "GPT partition path :") == 0) {
     idx= num[0] - 1;
     ret= Xorriso_search_eltorito_path(xorriso, et_imgs, elto_count,
                                       textpt, gpts[idx].ptype,
                                       &et_idx, &efi_boot_part, !!isohybrid);
     if(ret <= 0) {
       sprintf(xorriso->info_text,
               "Cannot make proposal to mark data file as GPT partition : ");
       Text_shellsafe(textpt, xorriso->info_text, 1);
       Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "SORRY", 0);
     }

   } else if(strcmp(name, "GPT start and size :") == 0) {
     idx= num[0] - 1;
     if(gpts[idx].ptype == 3)
       part_type= 0xef;
     else
       part_type= 0xcd;

     if(high_block * 4 < num[1] && num[2] > 0 && !gpts[idx].is_gap) {
       for(mbr_idx = 0; mbr_idx < mbr_count; mbr_idx++) {
         if(mbrpts[mbr_idx].start_block == num[1]) {
           if(mbrpts[mbr_idx].block_count != num[2] && !(flag & 1)) {
             sprintf(xorriso->info_text,
                     "GPT partition %d has same start block as MBR partition %d but different block count (%.f <> %.f)",
                     idx + 1, mbr_idx + 1, num[2],
                     (double) mbrpts[mbr_idx].block_count);
             Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "WARNING",
                                 0);
           }
       break;
         }
       }
       if(mbr_idx >= mbr_count) {
         if(appended_as_gpt == 1)
           appended_as_gpt= 2;
         sprintf(buf, "-append_partition %d 0x%lx ", idx + 1, part_type);
         Xorriso_add_intvl_adr(xorriso, buf, (uint64_t) num[1],
                               (uint64_t) (num[1] + num[2] - 1.0), "d",
                               imported_iso);
         Xorriso_record_cmd_linE
         buf[0]= 0;

#ifdef Not_any_more_because_padding_is_now_after_partitions
         appended_partition= 1;
#endif

       }

       /* Check for isohybri-ish MBR and GPT mix */
       if(mbr_count == 1 && mbrpts[0].ptype == 0xee && have_protective_msdos) {
         /* real GPT is not -part_like_isohybrid */
         ret= 0;
       } else {
         ret= Xorriso_search_eltorito_lba(xorriso, et_imgs, elto_count,
                                          (unsigned int) (num[1] / 4.0),
                                          &et_idx, 0);
       }
       if(ret > 0) {
         if(!(et_imgs[et_idx].do_gpt_basdat ||
              et_imgs[et_idx].do_gpt_hfsplus ||
              part_like_isohybrid)) {
           if(mkisofs)
             sprintf(buf, "-part_like_isohybrid");
           else
             sprintf(buf, "-boot_image any part_like_isohybrid=on");
           Xorriso_record_cmd_linE
           buf[0]= 0;
           part_like_isohybrid= 1;
           appended_as_gpt= 0;
         }
         /*  mark el torito for  -isohybrid-gpt-... */
         Xorriso_register_eltorito_gpt(xorriso, et_imgs + et_idx,
                                       gpts[idx].ptype, &efi_boot_part,
                                       &fe_dummy, 1);
       }

     } else if(gpts[idx].ptype == 3 && gpts[idx].has_path == 0 &&
               img_blocks >= num[1] + num[2] && !efi_boot_part) {
       if(mkisofs)
         sprintf(buf, "-efi-boot-part ");
       else
         sprintf(buf, "-boot_image any efi_boot_part=");
       Xorriso_add_intvl_adr(xorriso, buf, (uint64_t) num[1],
                             (uint64_t) (num[1] + num[2] - 1.0), "d",
                             imported_iso);
       efi_boot_part= 2;

     }

   } else if(strcmp(name, "APM block size     :") == 0) {
     if(mkisofs)
       sprintf(buf, "-apm-block-size %.f", num[0]);
     else
       sprintf(buf, "-boot_image any apm_block_size=%.f", num[0]);

   } else if(strcmp(name, "APM partition name :") == 0) {

     /* >>> ??? need command to set APM partition name for partition number */;

   } else if(strcmp(name, "APM partition path :") == 0) {
     idx= num[0] - 1;
     /* Check El Torito EFI boot images for same path */
     for(et_idx= 0; isohybrid && et_idx < elto_count; et_idx++)
       if(strcmp(et_imgs[et_idx].path, textpt) == 0) {
         if(apms[idx].ptype == 1) {
           et_imgs[et_idx].do_apm_hfsplus= 1;
           cared_for_apm= 1;
         }
     break;
       }

   } else if(strcmp(name, "APM start and size :") == 0) {
     idx= num[0] - 1;

     if(num[1] + num[2] <= img_blocks && apms[idx].ptype == 3 &&
        apms[idx].path == NULL && !have_hfsplus) {
       
       /* >>> HFS+ magic number */;
       /* >>> Read byte 1024 and 1025 after partition start
              Must be {'H', '+'}  (0x482b big endian)
       */;
       /* ??? >>> Do this recognition in libisofs ? */

       if(mkisofs)
         sprintf(buf, "-hfsplus");
       else
         sprintf(buf, "-hfsplus on");
       Xorriso_record_cmd_linE
       buf[0]= 0;

       /* Report commands for blessings and creator-type */
       ret= Findjob_new(&job, "/", 0);
       if(ret <= 0) {
         Xorriso_no_findjob(xorriso, "xorriso", 0);
         {ret= -1; goto ex;}
       }
       Findjob_set_action_target(job, 53, NULL, 0);
       xorriso->show_hfs_cmd_count= *cmd_count;
       xorriso->show_hfs_cmds= cmds;
       xorriso->show_hfs_cmd_flag= (flag & 1) | ((!!mkisofs) << 1);
       ret= Xorriso_findi(xorriso, job, NULL, (off_t) 0, NULL, "/",
                          &dir_stbuf, 0, 0);
       *cmd_count= xorriso->show_hfs_cmd_count;
       if(ret <= 0)
         goto ex;
       have_hfsplus= 1;
       cared_for_apm= 1;
     }

   } else if(strcmp(name, "MIPS-BE boot path  :") == 0) {
     if(mkisofs)
       sprintf(buf, "-mips-boot ");
     else
       sprintf(buf, "-boot_image any mips_path=");
     Text_shellsafe(textpt, buf, 1);

   } else if(strcmp(name, "MIPS-LE boot path  :") == 0) {
     if(mkisofs)
       sprintf(buf, "-mipsel-boot ");
     else
       sprintf(buf, "-boot_image any mipsel_path=");
     Text_shellsafe(textpt, buf, 1);

   } else if(strcmp(name, "SUN SPARC disklabel:") == 0) {
     if(mkisofs)
       sprintf(buf, "-sparc-label ");
     else
       sprintf(buf, "-boot_image any sparc_label=");
     Text_shellsafe(textpt, buf, 1);

   } else if(strcmp(name, "SPARC GRUB2 path   :") == 0) {
     if(mkisofs) {
       sprintf(buf, "-B ,");
       Xorriso_record_cmd_linE
       sprintf(buf, "--grub2-sparc-core ");
     } else
       sprintf(buf, "-boot_image grub grub2_sparc_core=");
     Text_shellsafe(textpt, buf, 1);
     cared_for_sparc= 1;

   } else if(strcmp(name, "SUN SPARC partition:") == 0) {
     have_sparc_part= 1;
     partno= id_tag= perms= num_blocks= 0;
     start_cyl= 0xffffffff;
     sscanf(contentpt, "%lu 0x%lx 0x%lx %lu %lu",
            &partno, &id_tag, &perms, &start_cyl, &num_blocks);
     if(partno > 0 && partno < 9 && start_cyl == 0 && 
        num_blocks >= img_blocks - 600 && num_blocks <= img_blocks &&
        ((partno == 1 && id_tag == 4) || (partno > 1 && id_tag == 2)))
       full_sparc_part|= (1 << (partno - 1));

   } else if(strcmp(name, "PALO header version:") == 0) {
     if(mkisofs)
       sprintf(buf, "-hppa-hdrversion %.f", num[0]);
     else
       sprintf(buf, "-boot_image any hppa_hdrversion=%.f", num[0]);

   } else if(strcmp(name, "HP-PA cmdline      :") == 0) {
     if(mkisofs)
       sprintf(buf, "-hppa-cmdline ");
     else
       sprintf(buf, "-boot_image any hppa_cmdline=");
     Text_shellsafe(textpt, buf, 1);

   } else if(strcmp(name, "HP-PA 32-bit kernel:") == 0) {
     if(mkisofs)
       sprintf(buf, "-hppa-kernel-32 ");
     else
       sprintf(buf, "-boot_image any hppa_kernel_32=");
     Text_shellsafe(textpt, buf, 1);

   } else if(strcmp(name, "HP-PA 64-bit kernel:") == 0) {
     if(mkisofs)
       sprintf(buf, "-hppa-kernel-64 ");
     else
       sprintf(buf, "-boot_image any hppa_kernel_64=");
     Text_shellsafe(textpt, buf, 1);

   } else if(strcmp(name, "HP-PA ramdisk      :") == 0) {
     if(mkisofs)
       sprintf(buf, "-hppa-ramdisk ");
     else
       sprintf(buf, "-boot_image any hppa_ramdisk=");
     Text_shellsafe(textpt, buf, 1);

   } else if(strcmp(name, "HP-PA bootloader   :") == 0) {
     if(mkisofs)
       sprintf(buf, "-hppa-bootloader ");
     else
       sprintf(buf, "-boot_image any hppa_bootloader=");
     Text_shellsafe(textpt, buf, 1);

   } else if(strcmp(name, "DEC Alpha ldr adr  :") == 0) {
     if(!have_alpha_ldr_path) {
       sprintf(xorriso->info_text,
               "Cannot enable DEC Alpha boot loader because it is not a data file in the ISO filesystem");
       Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "SORRY", 0);
     }

   } else if(strcmp(name, "DEC Alpha ldr path :") == 0) {
     if(mkisofs)
       sprintf(buf, "-alpha-boot ");
     else
       sprintf(buf, "-boot_image any alpha_boot=");
     Text_shellsafe(textpt, buf, 1);

   }
   
   if(buf[0])
     Xorriso_record_cmd_linE
 }

 if(appended_as_gpt == 2) {
   if(mkisofs)
     sprintf(buf, "-appended_part_as_gpt");
   else
     sprintf(buf, "-boot_image any appended_part_as=gpt");
   Xorriso_record_cmd_linE
 }

 if(have_sparc_part) {
   if(full_sparc_part == 255) {
     if(mkisofs) {
       sprintf(buf, "-G ");
       Xorriso_add_intvl_adr(xorriso, buf, (uint64_t) 0, (uint64_t) 15, "s",
                             imported_iso);
       Xorriso_record_cmd_linE
       did_sysarea= 1;
       sprintf(buf, "-B ...");
       Xorriso_record_cmd_linE
     } else {
       sprintf(buf, "-boot_image any system_area=");
       Xorriso_add_intvl_adr(xorriso, buf, (uint64_t) 0, (uint64_t) 15, "s",
                             imported_iso);
       Xorriso_record_cmd_linE
       did_sysarea= 1;
       for(i= 2; i <= 8; i++) {
         sprintf(buf, "-append_partition %d 0x00 .", i);
         Xorriso_record_cmd_linE
       }
     }
     cared_for_sparc= 1;
   } else if(!cared_for_sparc) {
     sprintf(xorriso->info_text,
       "Cannot enable SUN Disk Label because of non-trivial partition layout");
     Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "SORRY", 0);
   }
 }
 if(have_sysarea && !did_sysarea) {
   /* Zeroize old partition tables from -indev */
   if(mkisofs)
     sprintf(buf, "-G ");
   else
     sprintf(buf, "-boot_image any system_area=");
   Xorriso_add_intvl_adr(xorriso, buf, (uint64_t) 0, (uint64_t) 15, "s",
                         imported_iso | ptable_killer);
   Xorriso_record_cmd_linE
   did_sysarea= 1;
 }
 if(iso_mbr_part_type >= 0) {
   if(mkisofs)
     sprintf(buf, "-iso_mbr_part_type 0x%2.2x",
                  (unsigned int) iso_mbr_part_type);
   else
     sprintf(buf, "-boot_image any iso_mbr_part_type=0x%2.2x",
                  (unsigned int) iso_mbr_part_type);
   Xorriso_record_cmd_linE
 }

 /* Issue commands related to El Torito */
 if(elto_count <= 0)
   goto after_el_torito;

 if(efi_boot_part) {
   if(mkisofs)
     sprintf(buf, "-efi-boot-part --efi-boot-image");
   else
     sprintf(buf, "-boot_image any efi_boot_part=--efi-boot-image");
   Xorriso_record_cmd_linE
 }
 if(cat_path[0]) {
   if(mkisofs)
     sprintf(buf, "-c ");
   else
     sprintf(buf, "-boot_image any cat_path=");
   Text_shellsafe(cat_path, buf, 1);
 } else {
   if(mkisofs)
     sprintf(buf, "--boot-catalog-hide");
   else
     sprintf(buf, "-boot_image any cat_hidden=on");
 }
 Xorriso_record_cmd_linE
 for(idx= 0; idx < elto_count; idx++) {
   if(et_imgs[idx].ld_seg != 0 && et_imgs[idx].ld_seg != 0x07c0) {
     if(!(flag & 1)) {
       sprintf(xorriso->info_text,
              "Cannot enable EL Torito boot image #%d because its Load Segment is neither 0x0 nor 0x7c0",
              idx + 1);
       Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "SORRY", 0);
     }
 continue;
   }
   if(idx > 0) {
     if(mkisofs)
       sprintf(buf, "-eltorito-alt-boot");
     else
       sprintf(buf, "-boot_image any next");
     Xorriso_record_cmd_linE
   }
   if(et_imgs[idx].path[0] == 0) {

     /* >>> need way to eploit El Torito img blks : */;

     /* Check whether appended partition */;
     for(i= 0; i < mbr_count; i++)
       if((mbrpts[i].appended || !mbrpts[i].has_path) &&
          mbrpts[i].start_block == ((uint64_t) et_imgs[idx].lba) * 4 &&
          (mbrpts[i].block_count == (uint64_t) et_imgs[idx].ldsiz ||
           et_imgs[idx].ldsiz == 0 || et_imgs[idx].ldsiz == 1)) 
     break;
     if (i < mbr_count) {
       if(!mbrpts[i].appended) {
         mbrpts[i].appended= 1;
         if(!appended_as_gpt) {
           sprintf(buf, "-append_partition %lu 0x%lx ", (unsigned long) i + 1,
                         (unsigned long) mbrpts[i].ptype);
           Xorriso_add_intvl_adr(xorriso, buf,
                                 (uint64_t) mbrpts[i].start_block,
                                 ((uint64_t) mbrpts[i].start_block) +
                                 mbrpts[i].block_count - 1,
                                 "d", imported_iso);
           Xorriso_record_cmd_linE

#ifdef Not_any_more_because_padding_is_now_after_partitions
           appended_partition= 1;
#endif

           buf[0]= 0;
         }
       }
       sprintf(app_pseudo_paths[idx],
               "--interval:appended_partition_%d_start_%lus_size_%lud:all::",
               i + 1,
               (unsigned long) et_imgs[idx].lba,
               (unsigned long) mbrpts[i].block_count);
       et_imgs[idx].path= app_pseudo_paths[idx];
     }
     if (et_imgs[idx].path[0] == 0) {
       for(i= 0; i < gpt_count; i++) {
         if(have_protective_msdos && (
            gpts[i].start_block == ((uint64_t) et_imgs[idx].lba) * 4 &&
            (gpts[i].block_count == (uint64_t) et_imgs[idx].ldsiz ||
            et_imgs[idx].ldsiz == 0 || et_imgs[idx].ldsiz == 1)))
       break;
       }
       if (i < gpt_count) {
         sprintf(app_pseudo_paths[idx],
                 "--interval:appended_partition_%d_start_%lus_size_%lud:all::",
                 i + 1,
                 (unsigned long) et_imgs[idx].lba,
                 (unsigned long) gpts[i].block_count);
         et_imgs[idx].path= app_pseudo_paths[idx];
       }
     }
     if (et_imgs[idx].path[0] == 0) {
       if(!(flag & 1)) {
         sprintf(xorriso->info_text,
              "Cannot enable EL Torito boot image #%d because it is not a data file in the ISO filesystem",
              idx + 1);
         Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "SORRY", 0);
       }
       buf[0]= 0;
 continue;
     }
   }
   if(et_imgs[idx].platform_id != 0xef) {
     if(mkisofs) {
       if(prev_pltf != et_imgs[idx].platform_id) {
         sprintf(buf, "-eltorito-platform 0x%2.2x", et_imgs[idx].platform_id);
         Xorriso_record_cmd_linE
       }
       prev_pltf= et_imgs[idx].platform_id;
       sprintf(buf, "-b ");
     } else {
       sprintf(buf, "-boot_image %s bin_path=", et_imgs[idx].boot_image_type);
     }
   } else {
     if(mkisofs)
       sprintf(buf, "-e ");
     else
       sprintf(buf, "-boot_image %s efi_path=", et_imgs[idx].boot_image_type);
   }
   Text_shellsafe(et_imgs[idx].path, buf, 1);
   Xorriso_record_cmd_linE
   if(!mkisofs) {
     sprintf(buf, "-boot_image any platform_id=0x%2.2x",
                  et_imgs[idx].platform_id);
     Xorriso_record_cmd_linE
   }
   if(strcmp(et_imgs[idx].emul, "none") == 0) {
     if(mkisofs)
       sprintf(buf, "-no-emul-boot");
     else
       sprintf(buf, "-boot_image any emul_type=no_emulation");
   } else if(strcmp(et_imgs[idx].emul, "hd") == 0) {
     if(mkisofs)
       sprintf(buf, "-hard-disk-boot");
     else
       sprintf(buf, "-boot_image any emul_type=hard_disk");
   } else {
     if(mkisofs)
       buf[0]= 0;
     else
       sprintf(buf, "-boot_image any emul_type=diskette");
   }
   if(buf[0])
     Xorriso_record_cmd_linE
   if(et_imgs[idx].ldsiz >= 0) {
     if(mkisofs)
       sprintf(buf, "-boot-load-size %d", et_imgs[idx].ldsiz);
     else
       sprintf(buf, "-boot_image any load_size=%d", et_imgs[idx].ldsiz * 512);
     Xorriso_record_cmd_linE
   }
   if(et_imgs[idx].boot_info_table) {
     if(mkisofs)
       sprintf(buf, "-boot-info-table");
     else
       sprintf(buf, "-boot_image any boot_info_table=on");
     Xorriso_record_cmd_linE
   }
   if(et_imgs[idx].grub2_boot_info) {
     if(mkisofs)
       sprintf(buf, "--grub2-boot-info");
     else
       sprintf(buf, "-boot_image grub grub2_boot_info=on");
     Xorriso_record_cmd_linE
   }
   if(et_imgs[idx].id_string[0] != 0) {
     if(mkisofs)
       sprintf(buf, "-eltorito-id ");
     else
       sprintf(buf, "-boot_image any id_string=");
     Text_shellsafe(et_imgs[idx].id_string, buf, 1);
     Xorriso_record_cmd_linE
   }
   if(et_imgs[idx].sel_crit[0] != 0) {
     if(mkisofs)
       sprintf(buf, "-eltorito-selcrit ");
     else
       sprintf(buf, "-boot_image any sel_crit=");
     Text_shellsafe(et_imgs[idx].sel_crit, buf, 1);
     Xorriso_record_cmd_linE
   }
   if(et_imgs[idx].do_gpt_basdat) {
     if(mkisofs)
       sprintf(buf, "-isohybrid-gpt-basdat");
     else
       sprintf(buf, "-boot_image isolinux partition_entry=gpt_basdat");
     Xorriso_record_cmd_linE
   }
   if(et_imgs[idx].do_gpt_hfsplus) {
     if(mkisofs)
       sprintf(buf, "-isohybrid-gpt-hfsplus");
     else
       sprintf(buf, "-boot_image isolinux partition_entry=gpt_hfsplus");
     Xorriso_record_cmd_linE
   }
   if(et_imgs[idx].do_apm_hfsplus) {
     if(mkisofs)
       sprintf(buf, "-isohybrid-apm-hfsplus");
     else
       sprintf(buf, "-boot_image isolinux partition_entry=apm_hfsplus");
     Xorriso_record_cmd_linE
   }
 }
after_el_torito:

 if((apm_count > 0 && !cared_for_apm) && !(flag & 1)) {
   sprintf(xorriso->info_text,
           "Cannot make proposal to produce APM of loaded image");
   Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "SORRY", 0);
 }

#ifdef Not_any_more_because_padding_is_now_after_partitions

 if(appended_partition) {
   if(mkisofs)
     sprintf(buf, "-no-pad");
   else
     sprintf(buf, "-padding 0");
   Xorriso_record_cmd_linE
 }

#endif /* Not_any_more_because_padding_is_now_after_partitions */

 ret= 1;
ex:
 xorriso->show_hfs_cmds= NULL;
 Findjob_destroy(&job, 0);
 Xorriso_free_meM(apms);
 Xorriso_free_meM(gpts);
 Xorriso_free_meM(mbrpts);
 if(app_pseudo_paths != NULL) {
   for(i= 0; i < elto_count; i++)
     if(app_pseudo_paths[i] != NULL)
       Xorriso_free_meM(app_pseudo_paths[i]);
   Xorriso_free_meM(app_pseudo_paths);
 }
 Xorriso_free_meM(et_imgs);
 Xorriso_free_meM(lines);
 Xorriso_free_meM(buf);
 return(ret);

#undef Xorriso_record_cmd_linE

}


/* @param flag bit0= currently not significant:
                     report is about El Torito rather than System Area
               bit1= report -as mkisofs options
               bit15= dispose cmds
*/
static int Xorriso_report_to_cmd(struct XorrisO *xorriso,
                                 char **et_lines, int et_line_count,
                                 char **sa_lines, int sa_line_count,
                                 char ***cmds, int *cmd_count, int flag)
{
 int ret= 0, i;

 if(flag & (1 << 15))
   {ret= 1; goto ex;}
 *cmds= NULL;
 *cmd_count= 0;

 /* Count commands */
 ret= Xorriso_scan_report_lines(xorriso, et_lines, et_line_count,
                                sa_lines, sa_line_count, *cmds, cmd_count,
                                1 | (flag & 2));
 if(ret <= 0)
   goto ex;

 if(*cmd_count <= 0)
   {ret= 2; goto ex;}
 Xorriso_alloc_meM(*cmds, char *, *cmd_count);
 for(i= 0; i < *cmd_count; i++)
   (*cmds)[i]= NULL;
 
 /* Record commands */
 ret= Xorriso_scan_report_lines(xorriso, et_lines, et_line_count, 
                                sa_lines, sa_line_count, *cmds, cmd_count,
                                flag & 2);
 if(ret <= 0)
   goto ex;

 ret= 1;
ex:
 if(ret <= 0 || (flag & (1 << 15))) {
   if(*cmds != NULL) {
     for(i= 0; i < *cmd_count; i++)
       if((*cmds)[i] != NULL)
         Xorriso_free_meM((*cmds)[i]);
     Xorriso_free_meM(*cmds);
     *cmds= NULL;
   }
 }
 return(ret); 
}



static void Xorriso_report_lines(struct XorrisO *xorriso,
                                char **lines, int line_count)
{
 int i;

 for(i = 0; i < line_count ; i++) {
   sprintf(xorriso->result_line, "%s\n", lines[i]);
   Xorriso_result(xorriso,0);
 }
} 


/* @param flag bit0= report El Torito rather than System Area
               bit1= with form "cmd" do not report but rather execute
*/
int Xorriso_report_system_area(struct XorrisO *xorriso, char *form, int flag)
{
 int ret, line_count, cmd_count= 0, et_line_count= 0, sa_line_count= 0;
 int do_cmd= 0, as_mkisofs= 0, i, bin_count;
 char **lines = NULL, **et_lines= NULL, **sa_lines= NULL, **cmds= NULL;
 uint8_t guid[16];
 IsoImage *image;

 if(strcmp(form, "cmd") == 0 || strcmp(form, "as_mkisofs") == 0 || (flag & 2))
   do_cmd= 1;
 if(strcmp(form, "as_mkisofs") == 0)
   as_mkisofs= 1;

 if(strcmp(form, "help") == 0) {
   if(flag & 1)
     ret= iso_image_report_el_torito(NULL, &et_lines, &et_line_count, 1);
   else
     ret= iso_image_report_system_area(NULL, &sa_lines, &sa_line_count, 1);
   if(ret <= 0)
     goto ex;
   sprintf(xorriso->result_line,
"------------------------------------------------------------------------------\n");
   Xorriso_result(xorriso, 0);
   if(flag & 1)
   sprintf(xorriso->result_line, "With -report_el_torito \"plain\":\n");
   else
     sprintf(xorriso->result_line, "With -report_system_area \"plain\":\n");
   Xorriso_result(xorriso, 0);
   sprintf(xorriso->result_line,
"------------------------------------------------------------------------------\n");
   Xorriso_result(xorriso, 0);
   sprintf(xorriso->result_line, "\n");
   Xorriso_result(xorriso, 0);

 } else if(strcmp(form, "") == 0 || strcmp(form, "plain") == 0 || do_cmd) {
   ret= Xorriso_get_volume(xorriso, &image, 0);
   if(ret <= 0)
     goto ex;
   if(do_cmd || (flag & 1))
     ret= iso_image_report_el_torito(image, &et_lines, &et_line_count, 0);
   if(ret < 0)
     goto ex;
   if(do_cmd || !(flag & 1))
     ret= iso_image_report_system_area(image, &sa_lines, &sa_line_count, 0);
   if(ret < 0)
     goto ex;
   if(do_cmd) {
     ret= Xorriso_report_to_cmd(xorriso, et_lines, et_line_count,
                                sa_lines, sa_line_count, &cmds, &cmd_count,
                                (flag & 1) | (as_mkisofs << 1));
     if(ret <= 0)
       goto ex;
   }
 } else if(strncmp(form, "gpt_crc_of:", 11) == 0 && !(flag & 1)) {
   ret = Xorriso_gpt_crc(xorriso, form + 11, 0);
   goto ex;

 } else if(strcmp(form, "make_guid") == 0 && !(flag & 1)) {
   ret= Xorriso_make_guid(xorriso, xorriso->result_line, 0);
   if(ret < 0)
     goto ex;
   strcat(xorriso->result_line, "\n");
   Xorriso_result(xorriso,0);
   goto ex;

 } else if(strcmp(form, "gpt_disk_guid") == 0 && !(flag & 1)) {
   ret= Xorriso_get_volume(xorriso, &image, 0);
   if(ret <= 0)
     goto ex;
   ret= iso_image_report_system_area(image, &sa_lines, &sa_line_count, 0);
   if(ret <= 0)
     goto ex;
   for(i= 0; i < sa_line_count; i++) {
     if(strncmp(sa_lines[i], "GPT disk GUID      :      ", 26) == 0) {
       ret= Hex_to_bin(sa_lines[i] + 26, 16, &bin_count, guid, 0);
       if(ret < 0 || bin_count != 16)
   break;
       Xorriso_format_guid(xorriso, guid, xorriso->result_line, 0);
       strcat(xorriso->result_line, "\n");
       Xorriso_result(xorriso,0);
       ret= 1;
       goto ex;
     }
   }
   ret= 1;
   goto ex;
   
 } else {
   sprintf(xorriso->info_text,
           "%s form parameter not recognized: ",
           flag & 1 ? "-report_el_torito" : "-report_system_area");
   Text_shellsafe(form, xorriso->info_text, 1);
   Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "FAILURE", 0);
   ret= 0; goto ex;
 }
 if(ret < 0)
   goto ex;
 if(flag & 1) {
   lines= et_lines;
   line_count= et_line_count;
 } else {
   lines= sa_lines;
   line_count= sa_line_count;
 }
 if(!do_cmd) {
   if(lines == NULL || ret == 0) {
     if(flag & 1)
       strcpy(xorriso->info_text, "No El Torito information was loaded");
     else
       strcpy(xorriso->info_text, "No System Area was loaded");
     Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "NOTE", 0);
     ret= 2; goto ex;
   }
   if(line_count == 0) {
     if(flag & 1)
       strcpy(xorriso->info_text, "No El Torito information available");
     else
       strcpy(xorriso->info_text, "System Area only contains 0-bytes");
     Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "NOTE", 0);
     ret= 2; goto ex;
   }
 }
 if(flag & 2) {
   if(cmd_count > 0) {
     ret= Xorriso_execute_option(xorriso,
               "-boot_image any discard -boot_image any system_area=/dev/zero",
               1 | 16);
     if(ret <= 0)
       goto ex;
     for(i= 0; i < cmd_count; i++) {
       ret= Xorriso_execute_option(xorriso, cmds[i], 1 | 16);
       if(ret <= 0)
         goto ex;
     }
     sprintf(xorriso->info_text,
             "Replayed %d boot related commands", cmd_count);
     Xorriso_msgs_submit(xorriso, 0, xorriso->info_text, 0, "NOTE", 0);
   } else {
     Xorriso_msgs_submit(xorriso, 0,
                         "No proposals available for boot related commands",
                         0, "NOTE", 0);
     ret= 2; goto ex;
   }
 } else if(do_cmd) {
   Xorriso_report_lines(xorriso, cmds, cmd_count);
 } else {
   Xorriso_report_lines(xorriso, lines, line_count);
 }
 ret= 1;
ex:;
 Xorriso_report_to_cmd(xorriso, NULL, 0, NULL, 0, &cmds, &cmd_count, 1 << 15);
 if(et_lines != NULL)
   iso_image_report_el_torito(NULL, &et_lines, &et_line_count, 1 << 15);
 if(sa_lines != NULL)
   iso_image_report_system_area(NULL, &sa_lines, &sa_line_count, 1 << 15);
 return(ret);
}

