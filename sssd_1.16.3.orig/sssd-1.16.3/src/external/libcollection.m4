AC_SUBST(COLLECTION_CFLAGS)
AC_SUBST(COLLECTION_LIBS)

PKG_CHECK_MODULES(COLLECTION,
    collection >= 0.5.1,
    ,
    AC_MSG_ERROR("Please install libcollection-devel")
    )

