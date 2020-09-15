import setuptools

with open('README.md', 'r') as f:
    long_description = f.read()

setuptools.setup(
    name='crtk',
    version='0.0.23',
    author='Hao-Nan Zhu',
    license='MIT',
    author_email='hao-n.zhu@outlook.com',
    description='Smart Contract Reverse Engineering Toolkits',
    long_description=long_description,
    long_description_content_type='text/markdown',
    install_requires=[
        'pysha3'
    ],
    include_package_data=True,
    url='https://github.com/hao-n/crtk',
    packages=setuptools.find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
)
