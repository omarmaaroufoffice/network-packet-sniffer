from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="network-packet-sniffer",
    version="1.0.0",
    author="Omar Maarouf",
    author_email="omar.maarouf.office@gmail.com",
    description="A network packet sniffer with detailed traffic analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/omarmaaroufoffice/network-packet-sniffer",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.7",
    install_requires=[
        "scapy>=2.5.0",
        "pytest>=7.0.0",
    ],
) 