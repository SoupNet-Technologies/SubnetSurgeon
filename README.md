# Subnet Surgeon

Subnet Surgeon is a tool designed to aid in various subnetting calculations. This utility provides a user-friendly interface for network administrators, students, and IT professionals to quickly and accurately perform subnetting tasks.

## Features

- **Calculate Subnet ID**: Determine the subnet ID based on an IP address and subnet mask.
- **Calculate Subnet Mask**: Find the subnet mask based on a given subnet ID (CIDR notation).
- **Calculate Subnet Address (Subnets)**: Calculate the subnet address given the number of required subnets.
- **Calculate Subnet Address (Hosts)**: Determine the subnet address based on the number of required hosts.
- **Calculate Subnet Address (Host Bits)**: Calculate the subnet address based on the number of host bits.
- **Calculate Broadcast Address**: Identify the broadcast address for a given IP and subnet mask.
- **Calculate IP Range**: Determine the range of usable IP addresses within a subnet.
- **Calculate Number of Usable Hosts**: Calculate the number of usable hosts in a subnet based on the subnet mask.
- **Convert CIDR to Subnet Mask**: Convert CIDR notation to a subnet mask.
- **Convert Subnet Mask to CIDR**: Convert a subnet mask to CIDR notation.
- **Check if IP is in Subnet**: Verify whether a specific IP address is within a given subnet.

## Getting Started

### Prerequisites

- Python 3.x
- `tkinter` library (usually included with Python)
- `matplotlib` library

### Installation

1. **Clone the repository**:
   ```sh
   git clone https://github.com/SoupNet-Technologies/sntss.git
   ```
2. **Navigate to the project directory**:
   ```sh
   cd sntss
   ```
3. **Install the required libraries**:
   ```sh
   pip install matplotlib
   ```

### Running Subnet Surgeon

To start Subnet Surgeon, run the following command:
```sh
python sntss.py
```

## Usage

1. **Main Menu**: Upon launching the application, you will see a main menu with various buttons corresponding to different subnetting functions.
2. **Input Fields**: Enter the required values in the input fields (e.g., IP address, subnet mask).
3. **Calculate**: Click the corresponding button to perform the calculation.
4. **Results**: View the results displayed on the screen, along with any relevant plots or visualizations.

## Screenshots

Include screenshots of the application in use to provide a visual guide for users.

## Contributing

We welcome contributions to enhance Subnet Surgeon. To contribute:

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Commit your changes with descriptive messages.
4. Push your changes to your fork.
5. Open a pull request to merge your changes into the main repository.

