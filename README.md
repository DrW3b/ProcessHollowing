# Hollow Console Application

This console application demonstrates the technique of "Process Hollowing" using C#. Process Hollowing involves creating a new process and replacing its legitimate code with malicious shellcode. The shellcode executed by the process is responsible for performing unauthorized activities.

## Prerequisites

To compile and execute this code, you need:

- Microsoft Visual Studio or a compatible C# compiler.
- Windows operating system.

## How it Works

1. The program defines several structures and imports necessary functions from system libraries using P/Invoke.

2. It declares a `STARTUPINFO` struct that represents the startup information for the new process.

3. The `CreateProcess` function is called to create a new process with the specified executable (`C:\\Windows\\System32\\svchost.exe`).

4. After successfully creating the process, the program queries information about the process using `ZwQueryInformationProcess` from `ntdll.dll`.

5. The image base address is obtained from the process information using the `PROCESS_BASIC_INFORMATION` struct.

6. The code then reads the PE header of the newly created process to locate the entry point address.

7. The entry point address is retrieved by parsing the PE header and calculating the RVA (Relative Virtual Address) of the entry point.

8. The program overwrites the original entry point of the process with custom shellcode by using the `WriteProcessMemory` function.

9. Finally, the thread of the process is resumed using `ResumeThread`, allowing the replaced code (shellcode) to execute within the context of the new process.

## Usage

1. Open the project in Microsoft Visual Studio or any compatible C# IDE.

2. Build the project to compile the code.

3. Execute the resulting executable.

   **Note:** Ensure that you understand the implications of running this code as it involves process hollowing and executing shellcode within a process.

## Disclaimer

**Warning: The code provided in this repository is for educational purposes only. Please use it responsibly and at your own risk. Executing shellcode and performing process hollowing can be malicious activities and may violate laws and regulations. Be aware of the potential legal consequences and only use this code in controlled environments with appropriate permissions. The author cannot be held responsible for any misuse or damages caused by the use of this code.**
Coded by DrW3B
