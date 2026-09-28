/* pkcs11/pkcs11.h — version dispatcher
 *
 * Build with -DPKCS11_USE_V32 (or CMake option PKCS11_V32=ON) to use the
 * official OASIS PKCS#11 v3.2 headers.  The default is the legacy g10 Code
 * header which requires no platform macros.
 */
#ifdef PKCS11_USE_V32
# include "v3.2/pkcs11-platform.h"
# include "v3.2/pkcs11.h"
#else
# include "pkcs11-legacy.h"
#endif
