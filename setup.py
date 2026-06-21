"""
Setup configuration for the AI-driven IoT IDS system.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    requirements = requirements_path.read_text(encoding="utf-8").strip().split("\n")
    requirements = [req.strip() for req in requirements if req.strip() and not req.startswith("#")]

setup(
    name="ai-iot-ids",
    version="0.1.0",
    author="AI-IoT-IDS Team",
    author_email="team@ai-iot-ids.com",
    description="AI-driven Intrusion Detection System for IoT networks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ai-iot-ids/ai-iot-ids",
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "black>=23.0.0",
            "isort>=5.12.0",
            "mypy>=1.5.0",
            "flake8>=6.0.0",
            "pre-commit>=3.0.0",
        ],
        "kafka": ["kafka-python>=2.0.2"],
        "nats": ["nats-py>=2.3.0"],
        "mqtt": ["paho-mqtt>=1.6.0"],
        "elasticsearch": ["elasticsearch>=8.9.0"],
        "api": ["fastapi>=0.103.0", "uvicorn>=0.23.0"],
    },
    entry_points={
        "console_scripts": [
            "ai-iot-ids-gateway=ai_iot_ids.cli.gateway:main",
            "ai-iot-ids-inference=ai_iot_ids.cli.inference:main",
            "ai-iot-ids-config=ai_iot_ids.cli.config:main",
        ],
    },
    include_package_data=True,
    package_data={
        "ai_iot_ids": [
            "config/*.yaml",
            "rules/*.rules",
            "schemas/*.json",
        ],
    },
    zip_safe=False,
)