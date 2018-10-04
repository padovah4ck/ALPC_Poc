using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace ALPC_Poc
{
    public class HardLink
    {
        /*
        function Emit-UNICODE_STRING {
        param(
            [String]$Data
        )

        $UnicodeObject = New-Object UNICODE_STRING
        $UnicodeObject_Buffer = $Data
        [UInt16]$UnicodeObject.Length = $UnicodeObject_Buffer.Length*2
        [UInt16]$UnicodeObject.MaximumLength = $UnicodeObject.Length+1
        [IntPtr]$UnicodeObject.Buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($UnicodeObject_Buffer)
        [IntPtr]$InMemoryStruct = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(16) # enough for x32/x64
        [system.runtime.interopservices.marshal]::StructureToPtr($UnicodeObject, $InMemoryStruct, $true)

        $InMemoryStruct
        */


        private static IntPtr Emit_UNICODESTRING(string data)
        {
            UNICODE_STRING UnicodeObject = new ALPC_Poc.UNICODE_STRING();
            UnicodeObject.Length = (UInt16)(data.Length * 2);
            UnicodeObject.MaximumLength = (UInt16)(data.Length + 1);
            UnicodeObject.Buffer = Marshal.StringToHGlobalUni(data);
            IntPtr InMemoryStruct = Marshal.AllocHGlobal(16);
            Marshal.StructureToPtr(UnicodeObject, InMemoryStruct, true);
            return InMemoryStruct;
        }


        /*
    function Get-FullPathName {
        param(
            [String]$Path
        )

        $lpBuffer = New-Object -TypeName System.Text.StringBuilder
        $FnPortionAddress = [IntPtr]::Zero

        # Call to get buffer length
        $CallResult = [NtHardLink]::GetFullPathName($Path,1,$lpBuffer,[ref]$FnPortionAddress)

        if ($CallResult -ne 0) {
            # Set buffer length and re-call
            $lpBuffer.EnsureCapacity($CallResult)|Out-Null
            $CallResult = [NtHardLink]::GetFullPathName($Path,$lpBuffer.Capacity,$lpBuffer,[ref]$FnPortionAddress)
            $FullPath = "\??\" + $lpBuffer.ToString()
        } else {
            $FullPath = $false
        }

        # Return FullPath
        $FullPath
    }         
         */


        private static string GetFullPathName(string path)
        {
            string fullPath = "";
            StringBuilder lpBuffer = new StringBuilder();
            IntPtr fnPortionAddress = IntPtr.Zero;
            UInt32 result = NtHardLink.GetFullPathName(path, 1, lpBuffer, ref fnPortionAddress);

            if (result != 0)
            {
                int minCapacity = lpBuffer.EnsureCapacity((int)result);
                result = NtHardLink.GetFullPathName(path, (UInt32)lpBuffer.Capacity, lpBuffer, ref fnPortionAddress);
                fullPath = @"\??\" + lpBuffer.ToString();
                //fullPath = lpBuffer.ToString();
            }
            else
            {
                //big fail
                return "";
            }
            return fullPath;
        }


        /*
    function Get-NativeFileHandle {
        param(
            [String]$Path
        )

        $FullPath = Get-FullPathName -Path $Path
        if ($FullPath) {
            # IO.* does not support full path name on Win7
            if (![IO.File]::Exists($Path)) {
                Write-Verbose "[!] Invalid file path specified.."
                $false
                Return
            }
        } else {
            Write-Verbose "[!] Failed to retrieve fully qualified path.."
            $false
            Return
        }

        # Prepare NtOpenFile params
        [IntPtr]$hFile = [IntPtr]::Zero
        $ObjAttr = New-Object OBJECT_ATTRIBUTES
        $ObjAttr.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($ObjAttr)
        $ObjAttr.ObjectName = Emit-UNICODE_STRING -Data $FullPath
        $ObjAttr.Attributes = 0x40
        $IoStatusBlock = New-Object IO_STATUS_BLOCK

        # DesiredAccess = MAXIMUM_ALLOWED; ShareAccess = FILE_SHARE_READ
        $CallResult = [NtHardLink]::NtOpenFile([ref]$hFile,0x02000000,[ref]$ObjAttr,[ref]$IoStatusBlock,0x1,0x0)
        if ($CallResult -eq 0) {
            $Handle = $hFile
        } else {
            Write-Verbose "[!] Failed to acquire file handle, NTSTATUS($('{0:X}' -f $CallResult)).."
            $Handle = $false
        }

        # Return file handle
        $Handle
    }         
         */


        private static IntPtr GetNativeFileHandle(string path)
        {
            IntPtr handle = IntPtr.Zero, hFile = IntPtr.Zero;
            string fullPath = GetFullPathName(path);
            if(!string.IsNullOrEmpty(path))
            {
                if(!File.Exists(path))
                {
                    Console.WriteLine("[!] Invalid file path specified..");
                    return handle;
                }
            }
            else
            {
                Console.WriteLine("[!] Failed to retrieve fully qualified path..");
                return handle;
            }
            // Prepare NtOpenFile params
            OBJECT_ATTRIBUTES objAttr = new OBJECT_ATTRIBUTES();
            objAttr.Length = Marshal.SizeOf(objAttr);
            objAttr.ObjectName = Emit_UNICODESTRING(fullPath);
            objAttr.Attributes = 0x40;
            IO_STATUS_BLOCK ioStatusBlock = new IO_STATUS_BLOCK();

            // DesiredAccess = MAXIMUM_ALLOWED; ShareAccess = FILE_SHARE_READ
            UInt32 callResult = NtHardLink.NtOpenFile(ref hFile,0x02000000,ref objAttr,ref ioStatusBlock,0x1,0x0) ;
            if(callResult==0)
            {
                handle = hFile;
            }
            else
            {
                Console.WriteLine("[!] Failed to acquire file handle, NTSTATUS({0:X}).." , callResult );
            }
            return handle;
        }


        /*
    function Create-NtHardLink {
        param(
            [String]$Link,
            [String]$Target
        )

        $LinkFullPath = Get-FullPathName -Path $Link
        # IO.* does not support full path name on Win7
        $LinkParent = [IO.Directory]::GetParent($Link).FullName
        if (![IO.Directory]::Exists($LinkParent)) {
            Write-Verbose "[!] Invalid link folder path specified.."
            $false
            Return
        }
        

        # Create pFileLinkInformation & IOStatusBlock struct
        $FileLinkInformation = New-Object FILE_LINK_INFORMATION
        $FileLinkInformation.ReplaceIfExists = $true
        $FileLinkInformation.FileName = $LinkFullPath
        $FileLinkInformation.RootDirectory = [IntPtr]::Zero
        $FileLinkInformation.FileNameLength = $LinkFullPath.Length * 2
        $FileLinkInformationLen = [System.Runtime.InteropServices.Marshal]::SizeOf($FileLinkInformation)
        $pFileLinkInformation = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($FileLinkInformationLen)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($FileLinkInformation, $pFileLinkInformation, $true)
        $IoStatusBlock = New-Object IO_STATUS_BLOCK

        # Get handle to target
        $hTarget = Get-NativeFileHandle -Path $Target
        if (!$hTarget) {
            $false
            Return
        }

        # FileInformationClass => FileLinkInformation = 0xB
        $CallResult = [NtHardLink]::NtSetInformationFile($hTarget,[ref]$IoStatusBlock,$pFileLinkInformation,$FileLinkInformationLen,0xB)
        if ($CallResult -eq 0) {
            $true
        } else {
            Write-Verbose "[!] Failed to create hardlink, NTSTATUS($('{0:X}' -f $CallResult)).."
        }

        # Free file handle
        $CallResult = [NtHardLink]::CloseHandle($hTarget)
    }         
         */

        public static bool CreateNtHardLink(string link, string target)
        {
            string linkFullPath = GetFullPathName(link);
            // IO.* does not support full path name on Win7
            string linkParent = System.IO.Directory.GetParent(link).FullName;

            if (!System.IO.Directory.Exists(linkParent))
            {
                Console.WriteLine("[!] Invalid link folder path specified..");
                return false;
            }

            FILE_LINK_INFORMATION fileLinkInformation = new FILE_LINK_INFORMATION();
            fileLinkInformation.ReplaceIfExists = true;
            fileLinkInformation.FileName = linkFullPath;
            fileLinkInformation.RootDirectory = IntPtr.Zero;
            fileLinkInformation.FileNameLength = (UInt32)linkFullPath.Length * 2;
            int fileLinkInformationLen = System.Runtime.InteropServices.Marshal.SizeOf(fileLinkInformation);
            IntPtr pFileLinkInformation = System.Runtime.InteropServices.Marshal.AllocHGlobal(fileLinkInformationLen);

            System.Runtime.InteropServices.Marshal.StructureToPtr(fileLinkInformation, pFileLinkInformation, true);
            IO_STATUS_BLOCK ioStatusBlock = new IO_STATUS_BLOCK();

            // Get handle to target
            IntPtr hTarget = GetNativeFileHandle(target);
            if (hTarget == IntPtr.Zero) {
                Console.WriteLine("[!] Couldnt get file handle {0} ..", target);
                return false;
            }

            // FileInformationClass => FileLinkInformation = 0xB
            UInt32 result = NtHardLink.NtSetInformationFile(hTarget, ref ioStatusBlock, pFileLinkInformation, (UInt32)fileLinkInformationLen, 0xB);
            if (result==0)
            {
                // everything is OK
                bool bResult = NtHardLink.CloseHandle(hTarget);
                return true;
            } else
            {
                Console.WriteLine("[!] Failed to create hardlink, NTSTATUS({0:X})..", result);
                bool bResult = NtHardLink.CloseHandle(hTarget);
                return false;
            }
            
        }

    }
}
