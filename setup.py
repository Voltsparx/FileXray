from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = []
    for line in fh:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        requirements.append(line)

setup(
    name="FileXray",
    version="4.0.0",
    author="Voltsparx",
    author_email="voltsparx@gmail.com",
    description="Advanced Multimedia Forensic Analysis Tool for OSINT and Digital Forensics",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/voltsparx/FileXray",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Prototype",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Multimedia",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "filexray=fileXray:main",
        ],
    },
    keywords="forensics osint metadata exif analysis security multimedia",
    project_urls={
        "Bug Reports": "https://github.com/voltsparx/FileXray/issues",
        "Source": "https://github.com/voltsparx/FileXray",
    },
)