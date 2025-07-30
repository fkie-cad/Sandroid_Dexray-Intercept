import os
from setuptools import setup, find_packages
from os.path import abspath, dirname, join

# here - where we are.
here = os.path.abspath(os.path.dirname(__file__))

# Path to the about.py file
init_py_path = join(here, "src", "dexray_intercept", "about.py")

# Read version and author from about.py
with open(init_py_path) as f:
    exec(f.read())

# Fetches the content from README.md
# This will be used for the "long_description" field.
README_MD = open(join(dirname(abspath(__file__)), "README.md")).read()



# read the package requirements for install_requires
with open(os.path.join(here, 'requirements.txt'), 'r') as f:
    requirements = f.readlines()

def get_version():
    about = {}
    with open(init_py_path) as f:
        exec(f.read(), about)
    return about["__version__"]

def get_author():
    author = {}
    with open(init_py_path) as f:
        exec(f.read(), author)
    return author["__author__"]


setup(
    # pip install dexray-intercept
    name="dexray-intercept",
    version=get_version(),

    # The description that will be shown on PyPI.
    description="This project is part of the dynamic Sandbox Sandroid. Its purpose is to create runtime profiles to track the behavior of an Android application. This is done utilizing frida.",

    # The content that will be shown on your project page.
    # In this case, we're displaying whatever is there in our README.md file
    long_description=README_MD,

    # Now, we'll tell PyPI what language our README file is in.
    long_description_content_type="text/markdown",


    url="https://github.com/fkie-cad/Sandroid_Dexray-Intercept",

    author=get_author(),
    author_email="daniel.baier@fkie.fraunhofer.de",
    license='GPL v3',

     # include other files
    package_data={
        '': [ os.path.join(here, 'src/dexray_intercept/profiling.js') # the frida agent to do the profiling
         ],  
    },



    include_package_data=True,
    python_requires='>=3.6',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    install_requires=requirements,


    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Natural Language :: English",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: JavaScript",
        "Topic :: Security",
        "Topic :: Software Development :: Debuggers"
    ],

    # Keywords are tags that identify your project and help searching for it
    # This field is OPTIONAL
    keywords=["mobile", "instrumentation", "frida", "hook", "android"],

    entry_points={
            'console_scripts': [
            'ammm=dexray_intercept.ammm:main',
            'dexray-intercept=dexray_intercept.ammm:main',
        ],
    },
)
