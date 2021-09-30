from setuptools import setup, find_packages

__version__ = "0.1.0"


with open("README.md", "r") as f:
    long_description = f.read()

setup(
    name="PyDNS2",
    version=__version__,
    author="Jonathan",
    author_email="pybots.il@gmail.com",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jonatan1609/PyDNS2",
    packages=find_packages(),
    classifiers=[
        "Topic :: Internet :: Name Service (DNS)",
        "Topic :: System :: Networking"
    ],
    python_requires=">=3.5"
)
