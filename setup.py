#! /usr/bin/env python
#
'''
Setup script for Authentic 2
'''

import glob
import os
import shutil
import subprocess
import sys

try:
    from setuptools import Command
    from setuptools.command.build import build as _build
    from setuptools.errors import CompileError
except ImportError:
    from distutils.cmd import Command
    from distutils.command.build import build as _build
    from distutils.errors import CompileError

from setuptools import find_packages, setup
from setuptools.command.install_lib import install_lib as _install_lib
from setuptools.command.sdist import sdist as _sdist


class compile_translations(Command):
    description = 'compile message catalogs to MO files via django compilemessages'
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        curdir = os.getcwd()
        try:
            os.environ.pop('DJANGO_SETTINGS_MODULE', None)
            from django.core.management import call_command

            for dir in glob.glob('src/*'):
                for path, dirs, files in os.walk(dir):
                    if 'locale' not in dirs:
                        continue
                    os.chdir(os.path.realpath(path))
                    call_command('compilemessages')
                    os.chdir(curdir)
        except ImportError:
            print
            sys.stderr.write('!!! Please install Django >= 1.4 to build translations')
            print
            print
            os.chdir(curdir)


class compile_scss(Command):
    description = 'compile scss files into css files'
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        sass_bin = None
        for program in ('sassc', 'sass'):
            sass_bin = shutil.which(program)
            if sass_bin:
                break
        if not sass_bin:
            raise CompileError(
                'A sass compiler is required but none was found.  See sass-lang.com for choices.'
            )

        for path, dirnames, filenames in os.walk('src'):
            for filename in filenames:
                if not filename.endswith('.scss'):
                    continue
                if filename.startswith('_'):
                    continue
                subprocess.check_call(
                    [
                        sass_bin,
                        '%s/%s' % (path, filename),
                        '%s/%s' % (path, filename.replace('.scss', '.css')),
                    ]
                )


class build(_build):
    sub_commands = [('compile_translations', None), ('compile_scss', None)] + _build.sub_commands


class sdist(_sdist):
    sub_commands = [('compile_translations', None)] + _sdist.sub_commands

    def run(self):
        print('creating VERSION file')
        if os.path.exists('VERSION'):
            os.remove('VERSION')
        version = get_version()
        version_file = open('VERSION', 'w')
        version_file.write(version)
        version_file.close()
        _sdist.run(self)
        print('removing VERSION file')
        if os.path.exists('VERSION'):
            os.remove('VERSION')


class install_lib(_install_lib):
    def run(self):
        self.run_command('compile_translations')
        _install_lib.run(self)


def get_version():
    """Use the VERSION, if absent generates a version with git describe, if not
    tag exists, take 0.0- and add the length of the commit log.
    """
    if os.path.exists('VERSION'):
        with open('VERSION') as v:
            return v.read()
    if os.path.exists('.git'):
        p = subprocess.Popen(
            ['git', 'describe', '--dirty=.dirty', '--match=v*'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        result = p.communicate()[0]
        if p.returncode == 0:
            result = result.decode('ascii').strip()[1:]  # strip spaces/newlines and initial v
            if '-' in result:  # not a tagged version
                real_number, commit_count, commit_hash = result.split('-', 2)
                version = '%s.post%s+%s' % (real_number, commit_count, commit_hash)
            else:
                version = result.replace('.dirty', '+dirty')
            return version
        else:
            return '0.0.post%s' % len(subprocess.check_output(['git', 'rev-list', 'HEAD']).splitlines())
    return '0.0'


setup(
    name='authentic2',
    version=get_version(),
    license='AGPLv3+',
    description='Authentic 2, a versatile identity management server',
    url='http://dev.entrouvert.org/projects/authentic/',
    author="Entr'ouvert",
    author_email='authentic@listes.entrouvert.com',
    maintainer='Benjamin Dauvergne',
    maintainer_email='bdauvergne@entrouvert.com',
    scripts=('manage.py',),
    packages=find_packages('src'),
    package_dir={
        '': 'src',
    },
    include_package_data=True,
    install_requires=[
        'django>=4.2,<4.3',
        'requests>=2.3',
        'requests-oauthlib',
        'django-model-utils>=2.4',
        'dnspython>=1.10',
        'Django-Select2>5,<7.11',
        'django-tables2>=1.0,<2.5',
        'django-ratelimit<3',
        'gadjo>=0.53',
        'django-import-export>=1,<3.1',
        'djangorestframework>=3.9,<3.15',
        'Markdown>=2.1',
        'netaddr',
        'python-ldap>=3.3.1',
        'django-filter',
        'pycryptodomex',
        'django-mellon>=1.34',
        'jwcrypto>=0.3.1,<1.3',
        'cryptography',
        'XStatic-jQuery',
        'XStatic-jquery-ui',
        'xstatic-select2',
        'pillow',
        'tablib',
        'chardet',
        'attrs>17',
        'atomicwrites',
        'zxcvbn',
        'phonenumbers',
        'publik_django_templatetags@git+https://git.entrouvert.org/publik-django-templatetags.git',
    ],
    zip_safe=False,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'Intended Audience :: Legal Industry',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Telecommunications Industry',
        'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
    ],
    cmdclass={
        'build': build,
        'install_lib': install_lib,
        'compile_scss': compile_scss,
        'compile_translations': compile_translations,
        'sdist': sdist,
    },
)
