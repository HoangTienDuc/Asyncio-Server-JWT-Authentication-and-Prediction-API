from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext
ext_modules = [
    Extension("utils.apis",  ["utils/apis.py"]),
    Extension("utils.asymmetric_helper",  ["utils/asymmetric_helper.py"]),
    Extension("utils.encrypt_controller",  ["utils/encrypt_controller.py"]),
    Extension("utils.jwt_helper",  ["utils/jwt_helper.py"]),
    Extension("utils.prediction",  ["utils/prediction.py"]),
    Extension("common.global_vars",  ["common/global_vars.py"]),

]
for ext_module in ext_modules:
    ext_module.cython_directives = {'language_level': "3"}

setup(
    name = 'LVM',
    cmdclass = {'build_ext': build_ext},
    ext_modules = ext_modules
)