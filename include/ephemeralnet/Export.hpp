#pragma once

#if defined(_WIN32)
#  if defined(EPHEMERALNET_BUILD_SHARED)
#    if defined(ephemeralnet_core_EXPORTS)
#      define EPHEMERALNET_API __declspec(dllexport)
#    else
#      define EPHEMERALNET_API __declspec(dllimport)
#    endif
#  else
#    define EPHEMERALNET_API
#  endif
#else
#  if defined(EPHEMERALNET_BUILD_SHARED)
#    define EPHEMERALNET_API __attribute__((visibility("default")))
#  else
#    define EPHEMERALNET_API
#  endif
#endif
