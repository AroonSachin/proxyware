from setuptools import setup, find_packages
setup(
    name='proxyware',
    version='0.1',
    packages=find_packages(where='src'),  # Specify the source directory
    package_dir={'': 'src'},  # Tell setuptools that packages are under src
    # packages=find_packages()
    install_requires=[
        'mitmproxy',
        'paramiko', 
        "bcrypt==4.0.1"
    ],
    entry_points={
        'console_scripts': [
            'proxyware=proxyware.main:main',  # Adjust this if your main function is named differently
        ],
    },
    description='A CLI tool to intercept, edit, and send HTTP/S requests and responses.',
    author='Arun Sachin',
    author_email='aroonfendi@gamil.com',
    url='https://github.com/AroonSachin/proxyware',  # Replace with your repository URL
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
