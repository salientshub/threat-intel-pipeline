"""Minimal setuptools configuration for the Threat Intelligence Pipeline."""

from setuptools import find_packages, setup

setup(
    name="threat_intel_pipeline",
    version="1.0.0",
    description=(
        "Automated Cyber Threat Intelligence pipeline: "
        "fetch, enrich, STIX-ify, and push to SIEM."
    ),
    author="Security Engineering Team",
    author_email="security@example.com",
    url="https://github.com/your-org/threat_intel_pipeline",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28,<3",
        "stix2>=3.0,<4",
        "python-dotenv>=1.0,<2",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "requests-mock>=1.11",
            "black>=23.0",
            "flake8>=6.0",
            "pre-commit>=3.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "threat-intel=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
    ],
)
