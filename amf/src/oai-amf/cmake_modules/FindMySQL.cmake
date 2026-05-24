# Minimal MySQL finder for local bare-metal builds in this workspace.
# The original OAI build scripts usually provide this module externally.

find_path(
  MySQL_INCLUDE_DIR
  NAMES mysql/mysql.h mysql.h
  PATHS
    /usr/include
    /usr/include/mysql
    /usr/include/mariadb
)

find_library(
  MySQL_LIBRARY
  NAMES mysqlclient mariadb
  PATHS
    /usr/lib
    /usr/lib/x86_64-linux-gnu
    /lib
    /lib/x86_64-linux-gnu
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  MySQL
  REQUIRED_VARS MySQL_INCLUDE_DIR MySQL_LIBRARY
)

if(MySQL_FOUND)
  set(MySQL_INCLUDE_DIRS "${MySQL_INCLUDE_DIR}")
  set(MySQL_LIBRARIES "${MySQL_LIBRARY}")
endif()

mark_as_advanced(MySQL_INCLUDE_DIR MySQL_LIBRARY)
