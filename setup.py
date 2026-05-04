#!/usr/bin/env python
# -*- encoding: utf-8 -*-
import io
from setuptools import setup, find_packages


setup(name='Exjobb',
      version='0.1.0',
      description='Terraform vulnerability scanner and infrastructure environment setup',
      keywords='Exjobb',
      author='Ida Rynger Johnny Norrman',
      author_email='ida.rynger@gmail.com',
      url='https://github.com/iryn02/Exjobb',
      download_url='https://github.com/gnebbia/Exjobb/archive/v0.1.0.tar.gz',
      license='GPLv3',
      long_description=io.open(
          './docs/README.md', 'r', encoding='utf-8').read(),
      long_description_content_type="text/markdown",
      platforms='any',
      zip_safe=False,
      # http://pypi.python.org/pypi?%3Aaction=list_classifiers
      classifiers=['Development Status :: 1 - Planning',
                   'Programming Language :: Python',
                   'Programming Language :: Python :: 3',
                   'Programming Language :: Python :: 3.6',
                   'Programming Language :: Python :: 3.7',
                   'Programming Language :: Python :: 3.8',
                   ],
      packages=find_packages(exclude=('tests',)),
      include_package_data=True,
      install_requires=[],
      entry_points={
           'console_scripts':[
               'Exjobb = Exjobb.main:main',
           ]
      },
      )
