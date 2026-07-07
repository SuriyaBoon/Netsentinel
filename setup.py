from setuptools import setup, find_packages

setup(
    name="netsentinel",
    version="1.0.0",
    description="Multithreaded network recon & port scanner built to understand Nmap internals",
    author="Suriya Boonsanong",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "netsentinel=netsentinel.cli:main",
        ],
    },
)
