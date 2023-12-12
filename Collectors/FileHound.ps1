<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Dependencies: RSAT-Fileservices (DFSN PoSh Module and WMI Namespaces)

    1. Get DFS Namespaces
    2. Get Share Ntfs Permissions
        - Use DFS Targetfolders
        - Accept additional paths via list
        - Scan provided computers for shares via NetShareEnum

    3. Get Folder Permissions of Share toplevel

    OpSec:
        - does not need local admin permissions
            - ToDo: Verify & Test
        - does (!) need ntfs permission to read access rights on shares
            - ToDo: check event ids for audited folders
.EXAMPLE
    PS C:\> Invoke-Filehound
    Collects Fileshares and dumps outputs to the current working directory
.NOTES
    - This script includes functions from other projects published under the BSD 3-Clause:
        - Credits forActive Directory search and handling of Dfs objects is go to the PowerSploit project: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
            - Get-Domain by Will Schroeder aka @harmj0y
            - Get-DomainSearcher by Will Schroeder aka @harmj0y
            - (slightly modified) Get-DomainDFSShare by Ben Campbell aka @meatballs_
        - Credits for NetApi32 stuff go to the PSReflect-Functions project by @jaredcatkinson and includes work from the PSReflect Project by Matthew Graeber (@mattifestation)
    - This script includes the New-Output function of AzureHound.ps1 by Andy Robbins (@_wald0), Rohan Vazarkar (@cptjesus), Ryan Hausknecht (@haus3c)
#>

##REGION PSReflect / PSReflect-Functions
function New-InMemoryModule
{
<#
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

$Module = New-InMemoryModule -ModuleName Win32
#>

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}
function struct
{
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field
 
.DESCRIPTION

The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 'field' helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout,

        [System.Runtime.InteropServices.CharSet]
        $CharSet = [System.Runtime.InteropServices.CharSet]::Ansi
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'Class,Public,Sealed,BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    switch($CharSet)
    {
        Ansi{$StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AnsiClass}
        Auto{$StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AutoClass}
        Unicode{$StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::UnicodeClass}
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            
            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}

# A helper function used to reduce typing while defining struct
# fields.
function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,
        
        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,
        
        [Parameter(Position = 2)]
        [UInt16]
        $Offset,
        
        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}

# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.

function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}
function Add-Win32Type
{
<#
.SYNOPSIS

Creates a .NET type for an unmanaged Win32 function.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func
 
.DESCRIPTION

Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).

The 'func' helper function can be used to reduce typing when defining
multiple function definitions.

.PARAMETER DllName

The name of the DLL.

.PARAMETER FunctionName

The name of the target function.

.PARAMETER EntryPoint

The DLL export function name. This argument should be specified if the
specified function name is different than the name of the exported
function.

.PARAMETER ReturnType

The return type of the function.

.PARAMETER ParameterTypes

The function parameters.

.PARAMETER NativeCallingConvention

Specifies the native calling convention of the function. Defaults to
stdcall.

.PARAMETER Charset

If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.

.PARAMETER SetLastError

Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.

.PARAMETER Module

The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER Namespace

An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

.NOTES

Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()
            
            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}

function NetShareEnum {
<#
    .SYNOPSIS
    
    Returns open shares on the local (or a remote) machine.
    Note: anything above level 2 requires admin rights on a remote system.
    
    Author: Will Schroeder (@harmj0y)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    
    .DESCRIPTION
    
    This function will execute the NetShareEnum Win32API call to query
    a given host for open shares. This is a replacement for "net share \\hostname".
    
    .PARAMETER ComputerName
    
    Specifies the hostname to query for shares (also accepts IP addresses).
    Defaults to 'localhost'.
    
    .PARAMETER Level
    
    Specifies the level of information to query from NetShareEnum.
    Default of 1. Affects the result structure returned.
    
    .NOTES
        
        (func netapi32 NetShareEnum ([Int]) @(
            [String], # _In_ LPWSTR servername
            [Int], # _In_ DWORD level
            [IntPtr].MakeByRefType(), # _Out_ LPBYTE *bufptr
            [Int], # _In_ DWORD prefmaxlen
            [Int32].MakeByRefType(), # _Out_ LPDWORD entriesread
            [Int32].MakeByRefType(), # _Out_ LPDWORD totalentries
            [Int32].MakeByRefType() # _Inout_ LPDWORD resume_handle
        ) -EntryPoint NetShareEnum)
    
        (func netapi32 NetApiBufferFree ([Int]) @(
            [IntPtr] # _In_ LPVOID Buffer
        )
    
    .EXAMPLE
    
    
    .LINK
    
    https://msdn.microsoft.com/en-us/library/windows/desktop/bb525387(v=vs.85).aspx
#>

    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',

        [ValidateSet(0, 1, 2, 502, 503)]
        [String]
        $Level = 1
    )
    BEGIN{

    }
    PROCESS {

        ForEach ($Computer in $ComputerName) {
            $PtrInfo = [IntPtr]::Zero
            $EntriesRead = 0
            $TotalRead = 0
            $ResumeHandle = 0

            # get the raw share information
            $Result = $Netapi32::NetShareEnum($Computer, $Level, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

            # locate the offset of the initial intPtr
            $Offset = $PtrInfo.ToInt64()

            # work out how much to increment the pointer by finding out the size of the structure
            $Increment = Switch ($Level) {
                0   { $SHARE_INFO_0::GetSize() }
                1   { $SHARE_INFO_1::GetSize() }
                2   { $SHARE_INFO_2::GetSize() }
                502 { $SHARE_INFO_502::GetSize() }
                503 { $SHARE_INFO_503::GetSize() }
            }

            # 0 = success
            if (($Result -eq 0) -and ($Offset -gt 0)) {

                # parse all the result structures
                for ($i = 0; ($i -lt $EntriesRead); $i++) {
                    # create a new int ptr at the given offset and cast the pointer as our result structure
                    $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset

                    # grab the appropriate result structure
                    $Info = Switch ($Level) {
                        0   { $NewIntPtr -as $SHARE_INFO_0 }
                        1   { $NewIntPtr -as $SHARE_INFO_1 }
                        2   { $NewIntPtr -as $SHARE_INFO_2 }
                        502 { $NewIntPtr -as $SHARE_INFO_502 }
                        503 { $NewIntPtr -as $SHARE_INFO_503 }
                    }

                    # return all the sections of the structure - have to do it this way for V2
                    $Object = $Info | Select-Object *
                    $Offset = $NewIntPtr.ToInt64()
                    $Offset += $Increment
                    $Object
                }

                # free up the result buffer
                $Null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else {
                Write-Verbose "[NetShareEnum] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
            }
        }
    }
}

function NetApiBufferFree
{
    <#
    .SYNOPSIS

    The NetApiBufferFree function frees the memory that the NetApiBufferAllocate function allocates. Applications should also call NetApiBufferFree to free the memory that other network management functions use internally to return information.

    .DESCRIPTION

    The NetApiBufferFree function is used to free memory used by network management functions. This function is used in two cases:
    - To free memory explicitly allocated by calls in an application to the NetApiBufferAllocate function when the memory is no longer needed.
    - To free memory allocated internally by calls in an application to remotable network management functions that return information to the caller. The RPC run-time library internally allocates the buffer containing the return information.
    
    Many network management functions retrieve information and return this information as a buffer that may contain a complex structure, an array of structures, or an array of nested structures. These functions use the RPC run-time library to internally allocate the buffer containing the return information, whether the call is to a local computer or a remote server. For example, the NetServerEnum function retrieves a lists of servers and returns this information as an array of structures pointed to by the bufptr parameter. When the function is successful, memory is allocated internally by the NetServerEnum function to store the array of structures returned in the bufptr parameter to the application. When this array of structures is no longer needed, the NetApiBufferFree function should be called by the application with the Buffer parameter set to the bufptr parameter returned by NetServerEnum to free this internal memory used. In these cases, the NetApiBufferFree function frees all of the internal memory allocated for the buffer including memory for nested structures, pointers to strings, and other data.
    
    No special group membership is required to successfully execute the NetApiBufferFree function or any of the other ApiBuffer functions.

    .PARAMETER Buffer

    A pointer to a buffer returned previously by another network management function or memory allocated by calling the NetApiBufferAllocate function.

    .NOTES

    Author: Jared Atkinson (@jaredcatkinson)
    License: BSD 3-Clause
    Required Dependencies: PSReflect
    Optional Dependencies: None

    (func netapi32 NetApiBufferFree ([Int32]) @(
        [IntPtr]    # _In_ LPVOID Buffer
    ) -EntryPoint NetApiBufferFree)

    .LINK
    
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa370304(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $Buffer
    )

    $SUCCESS = $netapi32::NetApiBufferFree($Buffer)

    if($SUCCESS -ne 0)
    {
        throw "NetApiBufferFree Error: $($SUCCESS)"
    }
}
###END REGION PSReflect / PSReflect-Functions

###REGION AzureHound
function New-Output {
    [CmdletBinding()]
    Param(
        $Coll,
        $Type,
        $Directory
    )

    $Count = $Coll.Count

	if ($null -eq $Coll) {
        $Coll = New-Object System.Collections.ArrayList
    }

    # ConvertTo-Json consumes too much memory on larger objects, which can have millions
    # of entries in a large tenant. Write out the JSON structure a bit at a time to work
    # around this. This is a bit inefficient, but makes this work when the tenant becomes
    # too large.
    $FileName = $Directory + [IO.Path]::DirectorySeparatorChar + $(get-date -f yyyyMMddhhmmss) + "-" + $($Type) + ".json"
    Write-Information "Writing output for $($Type) to $FileName"
    try {
        $Stream = [System.IO.StreamWriter]::new($FileName)

        # Write file header JSON
        $Stream.WriteLine('{')
        $Stream.WriteLine("`t""meta"": {")
        $Stream.WriteLine("`t`t""count"": $Count,")
        $Stream.WriteLine("`t`t""type"": ""$($Type)"",")
        $Stream.WriteLine("`t`t""version"": 4")
        $Stream.WriteLine("`t},")        

        # Write data JSON
        $Stream.WriteLine("`t""data"": [")
        $Stream.Flush()

        $chunksize = 250
        $chunkarray = @()
        $parts = [math]::Ceiling($coll.Count / $chunksize)

        Write-Verbose "Chunking output in $chunksize item sections"
        for($n=0; $n -lt $parts; $n++){
            $start = $n * $chunksize
            $end = (($n+1)*$chunksize)-1
            $chunkarray += ,@($coll[$start..$end])
        }
        $Count = $chunkarray.Count

        $chunkcounter = 1
        $jsonout = ""
        ForEach ($chunk in $chunkarray) {
            Write-Verbose "Writing JSON chunk $chunkcounter/$Count"
            $jsonout = ConvertTo-Json -InputObject $chunk -Depth 3
            $jsonout = $jsonout.trimstart("[`r`n").trimend("`r`n]")
            $Stream.Write($jsonout)
            If ($chunkcounter -lt $Count) {
                $Stream.WriteLine(",")
            } Else {
                $Stream.WriteLine("")
            }
            $Stream.Flush()
            $chunkcounter += 1
        }
        $Stream.WriteLine("`t]")
        $Stream.WriteLine("}")
    } finally {
        $Stream.close()
    }
}
###END REGION AzureHound

###REGION PowerView
function Get-Domain {
    <#
        .SYNOPSIS
        Returns the domain object for the current (or specified) domain.
        Author: Will Schroeder (@harmj0y)  
        License: BSD 3-Clause  
        Required Dependencies: None  
        .DESCRIPTION
        Returns a System.DirectoryServices.ActiveDirectory.Domain object for the current
        domain or the domain specified with -Domain X.
        .PARAMETER Domain
        Specifies the domain name to query for, defaults to the current domain.
        .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
        .EXAMPLE
        Get-Domain -Domain testlab.local
        .EXAMPLE
        $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
        $Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
        Get-Domain -Credential $Cred
        .OUTPUTS
        System.DirectoryServices.ActiveDirectory.Domain
        A complex .NET domain object.
        .LINK
        http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG
    #>

    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Credential']) {

            Write-Verbose '[Get-Domain] Using alternate credentials for Get-Domain'

            if ($PSBoundParameters['Domain']) {
                $TargetDomain = $Domain
            }
            else {
                # if no domain is supplied, extract the logon domain from the PSCredential passed
                $TargetDomain = $Credential.GetNetworkCredential().Domain
                Write-Verbose "[Get-Domain] Extracted domain '$TargetDomain' from -Credential"
            }

            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $TargetDomain, $Credential.UserName, $Credential.GetNetworkCredential().Password)

            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "[Get-Domain] The specified domain '$TargetDomain' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['Domain']) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "[Get-Domain] The specified domain '$Domain' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[Get-Domain] Error retrieving the current domain: $_"
            }
        }
    }
}

function Get-DomainSearcher {
    <#
        .SYNOPSIS
        Helper used by various functions that builds a custom AD searcher object.
        Author: Will Schroeder (@harmj0y)  
        License: BSD 3-Clause  
        Required Dependencies: Get-Domain  
        .DESCRIPTION
        Takes a given domain and a number of customizations and returns a
        System.DirectoryServices.DirectorySearcher object. This function is used
        heavily by other LDAP/ADSI searcher functions (Verb-Domain*).
        .PARAMETER Domain
        Specifies the domain to use for the query, defaults to the current domain.
        .PARAMETER LDAPFilter
        Specifies an LDAP query string that is used to filter Active Directory objects.
        .PARAMETER Properties
        Specifies the properties of the output object to retrieve from the server.
        .PARAMETER SearchBase
        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.
        .PARAMETER SearchBasePrefix
        Specifies a prefix for the LDAP search string (i.e. "CN=Sites,CN=Configuration").
        .PARAMETER Server
        Specifies an Active Directory server (domain controller) to bind to for the search.
        .PARAMETER SearchScope
        Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).
        .PARAMETER ResultPageSize
        Specifies the PageSize to set for the LDAP searcher object.
        .PARAMETER ResultPageSize
        Specifies the PageSize to set for the LDAP searcher object.
        .PARAMETER ServerTimeLimit
        Specifies the maximum amount of time the server spends searching. Default of 120 seconds.
        .PARAMETER SecurityMasks
        Specifies an option for examining security information of a directory object.
        One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.
        .PARAMETER Tombstone
        Switch. Specifies that the searcher should also return deleted/tombstoned objects.
        .PARAMETER Credential
        A [Management.Automation.PSCredential] object of alternate credentials
        for connection to the target domain.
        .EXAMPLE
        Get-DomainSearcher -Domain testlab.local
        Return a searcher for all objects in testlab.local.
        .EXAMPLE
        Get-DomainSearcher -Domain testlab.local -LDAPFilter '(samAccountType=805306368)' -Properties 'SamAccountName,lastlogon'
        Return a searcher for user objects in testlab.local and only return the SamAccountName and LastLogon properties.
        .EXAMPLE
        Get-DomainSearcher -SearchBase "LDAP://OU=secret,DC=testlab,DC=local"
        Return a searcher that searches through the specific ADS/LDAP search base (i.e. OU).
        .OUTPUTS
        System.DirectoryServices.DirectorySearcher
    #>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBasePrefix,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit = 120,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $TargetDomain = $Domain

            if ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
                # see if we can grab the user DNS logon domain from environment variables
                $UserDomain = $ENV:USERDNSDOMAIN
                if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $UserDomain) {
                    $BindServer = "$($ENV:LOGONSERVER -replace '\\','').$UserDomain"
                }
            }
        }
        elseif ($PSBoundParameters['Credential']) {
            # if not -Domain is specified, but -Credential is, try to retrieve the current domain name with Get-Domain
            $DomainObject = Get-Domain -Credential $Credential
            $BindServer = ($DomainObject.PdcRoleOwner).Name
            $TargetDomain = $DomainObject.Name
        }
        elseif ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
            # see if we can grab the user DNS logon domain from environment variables
            $TargetDomain = $ENV:USERDNSDOMAIN
            if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $TargetDomain) {
                $BindServer = "$($ENV:LOGONSERVER -replace '\\','').$TargetDomain"
            }
        }
        else {
            # otherwise, resort to Get-Domain to retrieve the current domain object
            write-verbose "get-domain"
            $DomainObject = Get-Domain
            $BindServer = ($DomainObject.PdcRoleOwner).Name
            $TargetDomain = $DomainObject.Name
        }

        if ($PSBoundParameters['Server']) {
            # if there's not a specified server to bind to, try to pull a logon server from ENV variables
            $BindServer = $Server
        }

        $SearchString = 'LDAP://'

        if ($BindServer -and ($BindServer.Trim() -ne '')) {
            $SearchString += $BindServer
            if ($TargetDomain) {
                $SearchString += '/'
            }
        }

        if ($PSBoundParameters['SearchBasePrefix']) {
            $SearchString += $SearchBasePrefix + ','
        }

        if ($PSBoundParameters['SearchBase']) {
            if ($SearchBase -Match '^GC://') {
                # if we're searching the global catalog, get the path in the right format
                $DN = $SearchBase.ToUpper().Trim('/')
                $SearchString = ''
            }
            else {
                if ($SearchBase -match '^LDAP://') {
                    if ($SearchBase -match "LDAP://.+/.+") {
                        $SearchString = ''
                        $DN = $SearchBase
                    }
                    else {
                        $DN = $SearchBase.SubString(7)
                    }
                }
                else {
                    $DN = $SearchBase
                }
            }
        }
        else {
            # transform the target domain name into a distinguishedName if an ADS search base is not specified
            if ($TargetDomain -and ($TargetDomain.Trim() -ne '')) {
                $DN = "DC=$($TargetDomain.Replace('.', ',DC='))"
            }
        }

        $SearchString += $DN
        Write-Verbose "[Get-DomainSearcher] search base: $SearchString"

        if ($Credential -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[Get-DomainSearcher] Using alternate credentials for LDAP connection"
            # bind to the inital search object using alternate credentials
            $DomainObject = New-Object DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
        }
        else {
            # bind to the inital object using the current credentials
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
        }

        $Searcher.PageSize = $ResultPageSize
        $Searcher.SearchScope = $SearchScope
        $Searcher.CacheResults = $False
        $Searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All

        if ($PSBoundParameters['ServerTimeLimit']) {
            $Searcher.ServerTimeLimit = $ServerTimeLimit
        }

        if ($PSBoundParameters['Tombstone']) {
            $Searcher.Tombstone = $True
        }

        if ($PSBoundParameters['LDAPFilter']) {
            $Searcher.filter = $LDAPFilter
        }

        if ($PSBoundParameters['SecurityMasks']) {
            $Searcher.SecurityMasks = Switch ($SecurityMasks) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }

        if ($PSBoundParameters['Properties']) {
            # handle an array of properties to load w/ the possibility of comma-separated strings
            $PropertiesToLoad = $Properties| ForEach-Object { $_.Split(',') }
            $Null = $Searcher.PropertiesToLoad.AddRange(($PropertiesToLoad))
        }

        $Searcher
    }
}

function Get-DomainDFSShare {
    <#
    .SYNOPSIS
    Returns a list of all fault-tolerant distributed file systems
    for the current (or specified) domains.
    Author: Ben Campbell (@meatballs__)  
    License: BSD 3-Clause  
    Required Dependencies: Get-DomainSearcher  
    .DESCRIPTION
    This function searches for all distributed file systems (either version
    1, 2, or both depending on -Version X) by searching for domain objects
    matching (objectClass=fTDfs) or (objectClass=msDFS-Linkv2), respectively
    The server data is parsed appropriately and returned.
    .PARAMETER Domain
    Specifies the domains to use for the query, defaults to the current domain.
    .PARAMETER SearchBase
    The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
    Useful for OU queries.
    .PARAMETER Server
    Specifies an Active Directory server (domain controller) to bind to.
    .PARAMETER SearchScope
    Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).
    .PARAMETER ResultPageSize
    Specifies the PageSize to set for the LDAP searcher object.
    .PARAMETER ServerTimeLimit
    Specifies the maximum amount of time the server spends searching. Default of 120 seconds.
    .PARAMETER Tombstone
    Switch. Specifies that the searcher should also return deleted/tombstoned objects.
    .PARAMETER Credential
    A [Management.Automation.PSCredential] object of alternate credentials
    for connection to the target domain.
    .EXAMPLE
    Get-DomainDFSShare
    Returns all distributed file system shares for the current domain.
    .EXAMPLE
    Get-DomainDFSShare -Domain testlab.local
    Returns all distributed file system shares for the 'testlab.local' domain.
    .EXAMPLE
    $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
    Get-DomainDFSShare -Credential $Cred
    .OUTPUTS
    System.Management.Automation.PSCustomObject
    A custom PSObject describing the distributed file systems.
    .NOTES
    The output was modified to fit the needs of FileHound.
    #>
    
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
        [OutputType('System.Management.Automation.PSCustomObject')]
        [CmdletBinding()]
        Param(
            [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
            [ValidateNotNullOrEmpty()]
            [Alias('DomainName', 'Name')]
            [String[]]
            $Domain,
    
            [ValidateNotNullOrEmpty()]
            [Alias('ADSPath')]
            [String]
            $SearchBase,
    
            [ValidateNotNullOrEmpty()]
            [Alias('DomainController')]
            [String]
            $Server,
    
            [ValidateSet('Base', 'OneLevel', 'Subtree')]
            [String]
            $SearchScope = 'Subtree',
    
            [ValidateRange(1, 10000)]
            [Int]
            $ResultPageSize = 200,
    
            [ValidateRange(1, 10000)]
            [Int]
            $ServerTimeLimit,
    
            [Switch]
            $Tombstone,
    
            [Management.Automation.PSCredential]
            [Management.Automation.CredentialAttribute()]
            $Credential = [Management.Automation.PSCredential]::Empty,
    
            [ValidateSet('All', 'V1', '1', 'V2', '2')]
            [String]
            $Version = 'All'
        )
    
        BEGIN {
            $SearcherArguments = @{}
            if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
            if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
            if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
            if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
            if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
            if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
            if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
    
            function Parse-Pkt {
                [CmdletBinding()]
                Param(
                    [Byte[]]
                    $Pkt
                )
    
                $bin = $Pkt
                $blob_version = [bitconverter]::ToUInt32($bin[0..3],0)
                $blob_element_count = [bitconverter]::ToUInt32($bin[4..7],0)
                $offset = 8
                #https://msdn.microsoft.com/en-us/library/cc227147.aspx
                $object_list = @()
                for($i=1; $i -le $blob_element_count; $i++){
                    $blob_name_size_start = $offset
                    $blob_name_size_end = $offset + 1
                    $blob_name_size = [bitconverter]::ToUInt16($bin[$blob_name_size_start..$blob_name_size_end],0)
    
                    $blob_name_start = $blob_name_size_end + 1
                    $blob_name_end = $blob_name_start + $blob_name_size - 1
                    $blob_name = [System.Text.Encoding]::Unicode.GetString($bin[$blob_name_start..$blob_name_end])
    
                    $blob_data_size_start = $blob_name_end + 1
                    $blob_data_size_end = $blob_data_size_start + 3
                    $blob_data_size = [bitconverter]::ToUInt32($bin[$blob_data_size_start..$blob_data_size_end],0)
    
                    $blob_data_start = $blob_data_size_end + 1
                    $blob_data_end = $blob_data_start + $blob_data_size - 1
                    $blob_data = $bin[$blob_data_start..$blob_data_end]
                    switch -wildcard ($blob_name) {
                        "\siteroot" {  }
                        "\domainroot*" {
                            # Parse DFSNamespaceRootOrLinkBlob object. Starts with variable length DFSRootOrLinkIDBlob which we parse first...
                            # DFSRootOrLinkIDBlob
                            $root_or_link_guid_start = 0
                            $root_or_link_guid_end = 15
                            $root_or_link_guid = [byte[]]$blob_data[$root_or_link_guid_start..$root_or_link_guid_end]
                            $guid = New-Object Guid(,$root_or_link_guid) # should match $guid_str
                            $prefix_size_start = $root_or_link_guid_end + 1
                            $prefix_size_end = $prefix_size_start + 1
                            $prefix_size = [bitconverter]::ToUInt16($blob_data[$prefix_size_start..$prefix_size_end],0)
                            $prefix_start = $prefix_size_end + 1
                            $prefix_end = $prefix_start + $prefix_size - 1
                            $prefix = [System.Text.Encoding]::Unicode.GetString($blob_data[$prefix_start..$prefix_end])
    
                            $short_prefix_size_start = $prefix_end + 1
                            $short_prefix_size_end = $short_prefix_size_start + 1
                            $short_prefix_size = [bitconverter]::ToUInt16($blob_data[$short_prefix_size_start..$short_prefix_size_end],0)
                            $short_prefix_start = $short_prefix_size_end + 1
                            $short_prefix_end = $short_prefix_start + $short_prefix_size - 1
                            $short_prefix = [System.Text.Encoding]::Unicode.GetString($blob_data[$short_prefix_start..$short_prefix_end])
    
                            $type_start = $short_prefix_end + 1
                            $type_end = $type_start + 3
                            $type = [bitconverter]::ToUInt32($blob_data[$type_start..$type_end],0)
    
                            $state_start = $type_end + 1
                            $state_end = $state_start + 3
                            $state = [bitconverter]::ToUInt32($blob_data[$state_start..$state_end],0)
    
                            $comment_size_start = $state_end + 1
                            $comment_size_end = $comment_size_start + 1
                            $comment_size = [bitconverter]::ToUInt16($blob_data[$comment_size_start..$comment_size_end],0)
                            $comment_start = $comment_size_end + 1
                            $comment_end = $comment_start + $comment_size - 1
                            if ($comment_size -gt 0)  {
                                $comment = [System.Text.Encoding]::Unicode.GetString($blob_data[$comment_start..$comment_end])
                            }
                            $prefix_timestamp_start = $comment_end + 1
                            $prefix_timestamp_end = $prefix_timestamp_start + 7
                            # https://msdn.microsoft.com/en-us/library/cc230324.aspx FILETIME
                            $prefix_timestamp = $blob_data[$prefix_timestamp_start..$prefix_timestamp_end] #dword lowDateTime #dword highdatetime
                            $state_timestamp_start = $prefix_timestamp_end + 1
                            $state_timestamp_end = $state_timestamp_start + 7
                            $state_timestamp = $blob_data[$state_timestamp_start..$state_timestamp_end]
                            $comment_timestamp_start = $state_timestamp_end + 1
                            $comment_timestamp_end = $comment_timestamp_start + 7
                            $comment_timestamp = $blob_data[$comment_timestamp_start..$comment_timestamp_end]
                            $version_start = $comment_timestamp_end  + 1
                            $version_end = $version_start + 3
                            $version = [bitconverter]::ToUInt32($blob_data[$version_start..$version_end],0)
    
                            # Parse rest of DFSNamespaceRootOrLinkBlob here
                            $dfs_targetlist_blob_size_start = $version_end + 1
                            $dfs_targetlist_blob_size_end = $dfs_targetlist_blob_size_start + 3
                            $dfs_targetlist_blob_size = [bitconverter]::ToUInt32($blob_data[$dfs_targetlist_blob_size_start..$dfs_targetlist_blob_size_end],0)
    
                            $dfs_targetlist_blob_start = $dfs_targetlist_blob_size_end + 1
                            $dfs_targetlist_blob_end = $dfs_targetlist_blob_start + $dfs_targetlist_blob_size - 1
                            $dfs_targetlist_blob = $blob_data[$dfs_targetlist_blob_start..$dfs_targetlist_blob_end]
                            $reserved_blob_size_start = $dfs_targetlist_blob_end + 1
                            $reserved_blob_size_end = $reserved_blob_size_start + 3
                            $reserved_blob_size = [bitconverter]::ToUInt32($blob_data[$reserved_blob_size_start..$reserved_blob_size_end],0)
    
                            $reserved_blob_start = $reserved_blob_size_end + 1
                            $reserved_blob_end = $reserved_blob_start + $reserved_blob_size - 1
                            $reserved_blob = $blob_data[$reserved_blob_start..$reserved_blob_end]
                            $referral_ttl_start = $reserved_blob_end + 1
                            $referral_ttl_end = $referral_ttl_start + 3
                            $referral_ttl = [bitconverter]::ToUInt32($blob_data[$referral_ttl_start..$referral_ttl_end],0)
    
                            #Parse DFSTargetListBlob
                            $target_count_start = 0
                            $target_count_end = $target_count_start + 3
                            $target_count = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_count_start..$target_count_end],0)
                            $t_offset = $target_count_end + 1
    
                            for($j=1; $j -le $target_count; $j++){
                                $target_entry_size_start = $t_offset
                                $target_entry_size_end = $target_entry_size_start + 3
                                $target_entry_size = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_entry_size_start..$target_entry_size_end],0)
                                $target_time_stamp_start = $target_entry_size_end + 1
                                $target_time_stamp_end = $target_time_stamp_start + 7
                                # FILETIME again or special if priority rank and priority class 0
                                $target_time_stamp = $dfs_targetlist_blob[$target_time_stamp_start..$target_time_stamp_end]
                                $target_state_start = $target_time_stamp_end + 1
                                $target_state_end = $target_state_start + 3
                                $target_state = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_state_start..$target_state_end],0)
    
                                $target_type_start = $target_state_end + 1
                                $target_type_end = $target_type_start + 3
                                $target_type = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_type_start..$target_type_end],0)
    
                                $server_name_size_start = $target_type_end + 1
                                $server_name_size_end = $server_name_size_start + 1
                                $server_name_size = [bitconverter]::ToUInt16($dfs_targetlist_blob[$server_name_size_start..$server_name_size_end],0)
    
                                $server_name_start = $server_name_size_end + 1
                                $server_name_end = $server_name_start + $server_name_size - 1
                                $server_name = [System.Text.Encoding]::Unicode.GetString($dfs_targetlist_blob[$server_name_start..$server_name_end])
    
                                $share_name_size_start = $server_name_end + 1
                                $share_name_size_end = $share_name_size_start + 1
                                $share_name_size = [bitconverter]::ToUInt16($dfs_targetlist_blob[$share_name_size_start..$share_name_size_end],0)
                                $share_name_start = $share_name_size_end + 1
                                $share_name_end = $share_name_start + $share_name_size - 1
                                $share_name = [System.Text.Encoding]::Unicode.GetString($dfs_targetlist_blob[$share_name_start..$share_name_end])
    
                                $target_list += "\\$server_name\$share_name"
                                $t_offset = $share_name_end + 1
                            }
                        }
                    }
                    $offset = $blob_data_end + 1
                    $dfs_pkt_properties = @{
                        'Name' = $blob_name
                        'Prefix' = $prefix
                        'TargetList' = $target_list
                    }
                    $object_list += New-Object -TypeName PSObject -Property $dfs_pkt_properties
                    $prefix = $Null
                    $blob_name = $Null
                    $target_list = $Null
                }
    
                $servers = @()
                $object_list | ForEach-Object {
                    if ($_.TargetList) {
                        $_.TargetList | ForEach-Object {
                            $servers += $_.split('\')[2]
                        }
                    }
                }
    
                $servers
            }
    
            function Get-DomainDFSShareV1 {
                [CmdletBinding()]
                Param(
                    [String]
                    $Domain,
    
                    [String]
                    $SearchBase,
    
                    [String]
                    $Server,
    
                    [String]
                    $SearchScope = 'Subtree',
    
                    [Int]
                    $ResultPageSize = 200,
    
                    [Int]
                    $ServerTimeLimit,
    
                    [Switch]
                    $Tombstone,
    
                    [Management.Automation.PSCredential]
                    [Management.Automation.CredentialAttribute()]
                    $Credential = [Management.Automation.PSCredential]::Empty
                )
                Write-Verbose "[Get-DomainDFSShare] Searching V1  Namespaces"
                $DFSsearcher = Get-DomainSearcher @PSBoundParameters
    
                if ($DFSsearcher) {
                    $DFSshares = @()
                    $DFSsearcher.filter = '(&(objectClass=fTDfs))'
                    $Null = $DFSSearcher.PropertiesToLoad.AddRange(('remoteServerName','Name','pkt'))
    
                    try {
                        $Results = $DFSSearcher.FindAll()
                        $Results | Where-Object {$_} | ForEach-Object {
                            $Properties = $_.Properties
                            $Targets = $Properties.remoteservername
                            $Pkt = $Properties.pkt
    
                            $DFSshares += $Targets | ForEach-Object {
                                try {
                                    if ( $_.Contains('\') ) {
                                        New-Object -TypeName PSObject -Property @{
                                            'DfsRootName' = $Properties.name[0];
                                            'DfsPath'= $_
                                            'Host'= $_.split('\')[2]
                                        }
                                    }
                                }
                                catch {
                                    Write-Verbose "[Get-DomainDFSShare] Get-DomainDFSShareV1 error in parsing DFS share : $_"
                                }
                            }
                        }
                        if ($Results) {
                            try { $Results.dispose() }
                            catch {
                                Write-Verbose "[Get-DomainDFSShare] Get-DomainDFSShareV1 error disposing of the Results object: $_"
                            }
                        }
                        $DFSSearcher.dispose()
                        
                        <#
                        if ($pkt -and $pkt[0]) {
                            Parse-Pkt $pkt[0] | ForEach-Object {
                                # If a folder doesn't have a redirection it will have a target like
                                # \\null\TestNameSpace\folder\.DFSFolderLink so we do actually want to match
                                # on 'null' rather than $Null
                                if ($_ -ne 'null') {
                                    New-Object -TypeName PSObject -Property @{
                                        'DfsRoot' = $Properties.name[0]
                                        'RemoteServerName' =  $_
                                        'Target' =  "\\$_\\$($Properties.name[0])"
                                    }
                                }
                            }
                        }
                        #>
                    }
                    catch {
                        Write-Warning "[Get-DomainDFSShare] Get-DomainDFSShareV1 error : $_"
                    }

                    $DFSshares
                }
            }
    
            function Get-DomainDFSShareV2 {
                [CmdletBinding()]
                Param(
                    [String]
                    $Domain,
    
                    [String]
                    $SearchBase,
    
                    [String]
                    $Server,
    
                    [String]
                    $SearchScope = 'Subtree',
    
                    [Int]
                    $ResultPageSize = 200,
    
                    [Int]
                    $ServerTimeLimit,
    
                    [Switch]
                    $Tombstone,
    
                    [Management.Automation.PSCredential]
                    [Management.Automation.CredentialAttribute()]
                    $Credential = [Management.Automation.PSCredential]::Empty
                )
                Write-Verbose "[Get-DomainDFSShare] Searching V2  Namespaces"
                $DFSsearcher = Get-DomainSearcher @PSBoundParameters
    
                if ($DFSsearcher) {

                    $DFSshares = @()
                    $DFSsearcher.filter = '(&(objectClass=msDFS-Namespacev2))'
                    $Null = $DFSSearcher.PropertiesToLoad.AddRange(('msDFS-TargetListv2','cn'))

                    try {
                        $Results = $DFSSearcher.FindAll()

                        $Results | Where-Object {$_} | ForEach-Object {
                            
                            $Properties = $_.Properties
                            $DFSRoot = $Properties.cn
                            $target_list = $Properties.'msdfs-targetlistv2'[0]
                            $xml = [xml][System.Text.Encoding]::Unicode.GetString($target_list[2..($target_list.Length-1)])
                            $DFSshares += $xml.targets.ChildNodes | ForEach-Object {
                                try {
                                    $Target = $_.InnerText
                                    if ( $Target.Contains('\') ) {
                                        
                                        New-Object -TypeName PSObject -Property @{
                                            'DfsRootName' = "$DFSRoot"
                                            'DfsPath'= "$Target"
                                            'Host'= $Target.split('\')[2]
                                        }
                                    }
                                }
                                catch {
                                    Write-Verbose "[Get-DomainDFSShare] Get-DomainDFSShareV2 error in parsing target : $_"
                                }
                            }
                        }
                        if ($Results) {
                            try { $Results.dispose() }
                            catch {
                                Write-Verbose "[Get-DomainDFSShare] Error disposing of the Results object: $_"
                            }
                        }
                        $DFSSearcher.dispose()
                    }
                    catch {
                        Write-Warning "[Get-DomainDFSShare] Get-DomainDFSShareV2 error : $_"
                    }
                    $DFSshares
                }
            }
        }
    
        PROCESS {
            $DFSshares = @()
    
            if ($PSBoundParameters['Domain']) {
                ForEach ($TargetDomain in $Domain) {
                    $SearcherArguments['Domain'] = $TargetDomain
                    if ($Version -match 'all|1') {
                        $DFSshares += Get-DomainDFSShareV1 @SearcherArguments
                    }
                    if ($Version -match 'all|2') {
                        $DFSshares += Get-DomainDFSShareV2 @SearcherArguments
                    }
                }
            }
            else {
                if ($Version -match 'all|1') {
                    $DFSshares += Get-DomainDFSShareV1 @SearcherArguments
                }
                if ($Version -match 'all|2') {
                    $DFSshares += Get-DomainDFSShareV2 @SearcherArguments
                }
            }
    
            $DFSshares
        }
}

###END REGION PowerView

$DebugPreference = "Continue"
$VerbosePreference  = "Continue"
$InformationPreference = "Continue"

function Get-SidByIdentityTranslate{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [System.Security.Principal.IdentityReference]$Identity
    )

    try{
        $objectSid = $Identity.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty Value
    }
    catch [System.Security.Principal.IdentityNotMappedException]{
        Write-Debug "Could not map $($Identity.Value)"
        $objectSid = $Identity.Value
    }
    catch{
        Write-Warning "Error translating identity $($Identity.Value): $($_.Exception.Message)"
        Write-Error -ErrorRecord $_ -ErrorAction Continue
        $objectSid = $Identity.Value
    }
    
    return $objectSid.ToString()
}
function Invoke-NetShareEnum {
    <#
    .SYNOPSIS
        Helper function to NetShareEnum. Returns the NetShareEnum object for given computers.
    .EXAMPLE
        PS C:\> Invoke-NetShareEnum -Computers @("FILE01.contoso.local")
    #>
    [CmdletBinding()]
    Param(
        [string[]]$Computers
    )

    $Module = New-InMemoryModule -ModuleName "FileHound"

    if( $null -eq $SHARE_INFO_0 ){
        $SHARE_INFO_0 = struct $Module SHARE_INFO_0 @{
            shi0_netname = field 0 String -MarshalAs @('LPWStr')
        }
    }
    
    if( $null -eq $SHARE_INFO_1 ){
        $SHARE_INFO_1 = struct $Module SHARE_INFO_1 @{
            shi1_netname = field 0 String -MarshalAs @('LPWStr')
            shi1_type    = field 1 UInt32
            shi1_remark  = field 2 String -MarshalAs @('LPWStr')
        }
    }
    
    if( $null -eq $SHARE_INFO_2 ){
        $SHARE_INFO_2 = struct $Module SHARE_INFO_2 @{
            shi2_netname      = field 0 String -MarshalAs @('LPWStr')
            shi2_type         = field 1 UInt32
            shi2_remark       = field 2 String -MarshalAs @('LPWStr')
            shi2_permissions  = field 3 UInt32
            shi2_max_uses     = field 4 UInt32
            shi2_current_uses = field 5 UInt32
            shi2_path         = field 6 String -MarshalAs @('LPWStr')
            shi2_passwd       = field 7 String -MarshalAs @('LPWStr')
        }
    }
    
    if ( $null -eq $SHARE_INFO_502 ){
        $SHARE_INFO_502 = struct $Module SHARE_INFO_502 @{
            shi502_netname             = field 0 String -MarshalAs @('LPWStr')
            shi502_type                = field 1 UInt32
            shi502_remark              = field 2 String -MarshalAs @('LPWStr')
            shi502_permissions         = field 3 UInt32
            shi502_max_uses            = field 4 UInt32
            shi502_current_uses        = field 5 UInt32
            shi502_path                = field 6 String -MarshalAs @('LPWStr')
            shi502_passwd              = field 7 String -MarshalAs @('LPWStr')
            shi502_reserved            = field 8 UInt32
            shi502_security_descriptor = field 9 IntPtr
        }
    }
    
    if( $null -eq $SHARE_INFO_503 ){
        $SHARE_INFO_503 = struct $Module SHARE_INFO_503 @{
            shi503_netname             = field 0 String -MarshalAs @('LPWStr')
            shi503_type                = field 1 UInt32
            shi503_remark              = field 2 String -MarshalAs @('LPWStr')
            shi503_permissions         = field 3 UInt32
            shi503_max_uses            = field 4 UInt32
            shi503_current_uses        = field 5 UInt32
            shi503_path                = field 6 String -MarshalAs @('LPWStr')
            shi503_passwd              = field 7 String -MarshalAs @('LPWStr')
            shi503_servername          = field 8 String -MarshalAs @('LPWStr')
            shi503_reserved            = field 9 UInt32
            shi503_security_descriptor = field 10 IntPtr
        }
    }
    
    $FunctionDefinitions = @( 
    
        #region netapi32
        (func netapi32 DsEnumerateDomainTrusts ([Int32]) @(
            [String],                   # _In_opt_ LPTSTR            ServerName
            [UInt32],                   # _In_     ULONG             Flags
            [IntPtr].MakeByRefType(),   # _Out_    PDS_DOMAIN_TRUSTS *Domains
            [IntPtr].MakeByRefType()    # _Out_    PULONG            DomainCount
        ) -EntryPoint DsEnumerateDomainTrusts),
    
        (func netapi32 DsGetSiteName ([Int32]) @(
            [String],                   # _In_  LPCTSTR ComputerName
            [IntPtr].MakeByRefType()    # _Out_ LPTSTR  *SiteName
        ) -EntryPoint DsGetSiteName),
    
        (func netapi32 NetApiBufferFree ([Int32]) @(
            [IntPtr]    # _In_ LPVOID Buffer
        ) -EntryPoint NetApiBufferFree),
    
        (func netapi32 NetConnectionEnum ([Int32]) @(
            [String],                   # _In_    LMSTR   servername
            [String],                   # _In_    LMSTR   qualifier
            [Int32],                    # _In_    LMSTR   qualifier
            [IntPtr].MakeByRefType(),   # _Out_   LPBYTE  *bufptr
            [Int32],                    # _In_    DWORD   prefmaxlen
            [Int32].MakeByRefType(),    # _Out_   LPDWORD entriesread
            [Int32].MakeByRefType(),    # _Out_   LPDWORD totalentries
            [Int32].MakeByRefType()     # _Inout_ LPDWORD resume_handle
        ) -EntryPoint NetConnectionEnum),
    
        (func netapi32 NetFileEnum ([Int32]) @(
            [String],                   # _In_    LMSTR      servername
            [String],                   # _In_    LMSTR      basepath
            [String],                   # _In_    LMSTR      username
            [Int32],                    # _In_    DWORD      level
            [IntPtr].MakeByRefType(),   # _Out_   LPBYTE     *bufptr
            [Int32],                    # _In_    DWORD      prefmaxlen
            [Int32].MakeByRefType(),    # _Out_   LPDWORD    entriesread
            [Int32].MakeByRefType(),    # _Out_   LPDWORD    totalentries
            [Int32].MakeByRefType()     # _Inout_ PDWORD_PTR resume_handle
        ) -EntryPoint NetFileEnum),
    
        (func netapi32 NetGetAnyDCName ([Int32]) @(
            [String],                   # _In_  LPCWSTR servername
            [String],                   # _In_  LPCWSTR domainname
            [IntPtr].MakeByRefType()    # _Out_ LPBYTE  *bufptr
        ) -EntryPoint NetGetAnyDCName),
    
        (func netapi32 NetGetDCName ([Int32]) @(
            [String],                   # _In_  LPCWSTR servername
            [String],                   # _In_  LPCWSTR domainname
            [IntPtr].MakeByRefType()    # _Out_ LPBYTE  *bufptr
        ) -EntryPoint NetGetDCName),
    
        (func netapi32 NetLocalGroupAddMembers ([Int32]) @(
            [String],                   # _In_ LPCWSTR servername
            [String],                   # _In_ LPCWSTR groupname
            [Int32],                    # _In_ DWORD   level
            [IntPtr].MakeByRefType(),   # _In_ LPBYTE  buf
            [Int32]                     # _In_ DWORD   totalentries
        ) -EntryPoint NetLocalGroupAddMembers),
    
        (func netapi32 NetLocalGroupDelMembers ([Int32]) @(
            [String],                   # _In_ LPCWSTR servername
            [String],                   # _In_ LPCWSTR groupname
            [Int32],                    # _In_ DWORD   level
            [IntPtr],                   # _In_ LPBYTE  buf
            [Int32]                     # _In_ DWORD   totalentries
        ) -EntryPoint NetLocalGroupDelMembers),
    
        (func netapi32 NetLocalGroupEnum ([Int32]) @(
            [String],                   # _In_    LPCWSTR    servername
            [Int32],                    # _In_    DWORD      level
            [IntPtr].MakeByRefType(),   # _Out_   LPBYTE     *bufptr
            [Int32],                    # _In_    DWORD      prefmaxlen
            [Int32].MakeByRefType(),    # _Out_   LPDWORD    entriesread
            [Int32].MakeByRefType(),    # _Out_   LPDWORD    totalentries
            [Int32].MakeByRefType()     # _Inout_ PDWORD_PTR resumehandle
        ) -EntryPoint NetLocalGroupEnum),
    
        (func netapi32 NetLocalGroupGetMembers ([Int32]) @(
            [String],
            [String],
            [Int32],
            [IntPtr].MakeByRefType(),
            [Int32], 
            [Int32].MakeByRefType(),
            [Int32].MakeByRefType(),
            [Int32].MakeByRefType()
        ) -EntryPoint NetLocalGroupGetMembers),
    
        (func netapi32 NetSessionEnum ([Int32]) @(
            [String],                   # _In_    LPWSTR  servername
            [String],                   # _In_    LPWSTR  UncClientName
            [String],                   # _In_    LPWSTR  username
            [Int32],                    # _In_    DWORD   level
            [IntPtr].MakeByRefType(),   # _Out_   LPBYTE  *bufptr
            [Int32],                    # _In_    DWORD   prefmaxlen
            [Int32].MakeByRefType(),    # _Out_   LPDWORD entriesread
            [Int32].MakeByRefType(),    # _Out_   LPDWORD totalentries
            [Int32].MakeByRefType()     # _Inout_ LPDWORD resume_handle
        ) -EntryPoint NetSessionEnum),
    
        (func netapi32 NetShareAdd ([Int32]) @(
            [String],                   # _In_  LPWSTR  servername
            [Int32],                    # _In_  DWORD   level
            [IntPtr],                   # _In_  LPBYTE  buf
            [Int32].MakeByRefType()     # _Out_ LPDWORD parm_err
        ) -EntryPoint NetShareAdd),
    
        (func netapi32 NetShareDel ([Int32]) @(
            [String],                   # _In_  LPWSTR  servername
            [String],                   # _In_  LPWSTR  netname
            [Int32]                     # _In_  DWORD   reserved
        ) -EntryPoint NetShareDel),
    
        (func netapi32 NetShareEnum ([Int32]) @(
            [String],                                   # _In_    LPWSTR  servername
            [Int32],                                    # _In_    DWORD   level
            [IntPtr].MakeByRefType(),                   # _Out_   LPBYTE  *bufptr
            [Int32],                                    # _In_    DWORD   prefmaxlen
            [Int32].MakeByRefType(),                    # _Out_   LPDWORD entriesread
            [Int32].MakeByRefType(),                    # _Out_   LPDWORD totalentries
            [Int32].MakeByRefType()                     # _Inout_ LPDWORD resume_handle
        ) -EntryPoint NetShareEnum),
    
        (func netapi32 NetWkstaUserEnum ([Int32]) @(
            [String],                   # _In_    LPWSTR  servername
            [Int32],                    # _In_    DWORD   level
            [IntPtr].MakeByRefType(),   # _Out_   LPBYTE  *bufptr
            [Int32],                    # _In_    DWORD   prefmaxlen
            [Int32].MakeByRefType(),    # _Out_   LPDWORD entriesread
            [Int32].MakeByRefType(),    # _Out_   LPDWORD totalentries
            [Int32].MakeByRefType()     # _Inout_ LPDWORD resumehandle
        ) -EntryPoint NetWkstaUserEnum)
        #endregion netapi32
    )
    
    $Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace PSReflectFunctions
    $netapi32 = $Types['netapi32']

    Write-Information "Starting to scan $($Computers.Count) computers for fileshares via NetShareEnum"
    $ShareCollection = New-Object System.Collections.ArrayList
    foreach( $computer in $Computers ){
        Write-Verbose "Enumerating shares on $($computer)"
        $shares = NetShareEnum -Level 2 -ComputerName $computer
        
        if( $shares){
            $EnumObject = [PSCustomObject]@{
                computer = "$computer"
                shares = $shares
            }
            $null = $ShareCollection.Add($EnumObject)
        }
        else{
            Write-Verbose "No shares returned for computer $computer"
        }
    }

    return $ShareCollection
}

function Get-PrincipalTypeBySid {
    [CmdletBinding()]
    Param(
        [string]$Identity
    )

    Write-Debug "Getting object type for $($Identity)"

    try{
        if( -not ($Identity  -like "S-1-5**") ){
            #Todo: Make this way better...
            return "BUILTIN"
        }
        else{
            $obj = New-Object System.Security.Principal.SecurityIdentifier $Identity
            $SidBinary = New-Object Byte[] $obj.BinaryLength
            $obj.GetBinaryForm($SidBinary,0)
            $SidBinary | Foreach-Object { $SidSearch += $("\{0:x2}" -f $_) }
            $DomainSearcher = Get-DomainSearcher -LDAPFilter "(objectSID=$($SidSearch))"
            $result = $DomainSearcher.FindOne()
            $objectCategory = $result.Properties.objectcategory

            if($objectCategory -like "CN=Person,*"){
                return "User"
            }
            elseif($objectCategory -like "CN=Computer,*"){
                return "Computer"
            }
            elseif($objectCategory -like "CN=Group,*"){
                return "Group"
            }
            elseif($null -eq $objectCategory){
                Write-Warning "Object category is null"
                return "UNKNOWN"
            }
            else{
                Write-Warning "unimplemented objectcategory: $($objectCategory)"
                return "UNKNOWN"
            }
        }
    }
    catch{
        Write-Warning "Error getting principaltype for identity $($Identity): $($_.Exception.Message)"
        Write-Error -ErrorRecord $_ -ErrorAction Stop
    }
}

function Get-ObjectIdForBloodhound {
    <#
    .SYNOPSIS
        Checks if a SID is well known and transforms well known SIDs for Bloodhound.
    .DESCRIPTION
        Bloodhound uses the format <Domain FQDN>-<ObjectSid> for well known objects in Active Directory. 
        The function checks if the RID is below 1000 and adds the given domain name to the Sid.
    .EXAMPLE
        PS C:\> Get-ObjectIdForBloodHound -Identifier "S-1-5-32-545" -Domain "contoso.local"
        PS C:\> CONTOSO.LOCAL-S-1-5-32-545
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Identifier,
        [Parameter(Mandatory=$true)]
        [string]$Domain
    )

    [int]$RID = $Identifier.Split("-")[$Identifier.Split("-").Count -1]
    if( $RID -le 1000){
        $BloodhoundId = "$($Domain.ToUpper())-$($Identifier)"
    }
    else{
        $BloodhoundId = $Identifier
    }

    return $BloodhoundId

}

function Invoke-Filehound {
    <#
    .SYNOPSIS
        This script tries to enumerate fileshares and access rights to those. Results are put out into a JSON which can be ingested by BloodHound.
    .DESCRIPTION
        Filehound tries to enumerate fileshares by:
            - querying for Dfs Namespaces and resolving their target folders
            - doing a NetShareEnum against all 
    .EXAMPLE
        PS C:\> <example usage>
        Explanation of what the example does
    .INPUTS
        Inputs (if any)
    .OUTPUTS
        Output (if any)
    .NOTES
        General notes
    #>
    [CmdletBinding()]
    Param(
        [string]$Domain,
        [string[]]$Computers,
        [string[]]$AdditionalPaths,
        [Parameter(Mandatory=$False)][String]$OutputDirectory = $(Get-Location)
    )

    if( [String]::IsNullOrWhiteSpace($Domain) -or [String]::IsNullOrEmpty($Domain) ){
        $Domain = Get-Domain | Select-Object -ExpandProperty Name
        Write-Verbose "No domainname provided, using $($Domain)"
    }

    Write-Information "Collecting DFS-Namespaces"
    $DfsNamespaces = Get-DomainDFSShare -Domain $Domain
    $DfsRoots = $DfsNamespaces | Select-Object -Unique -ExpandProperty DfsRootName
    Write-Information "Found $($DfsRoots.Count) namespaces"
    
    Write-Information "Building Dfs Objects"
    $DfsCollection = New-Object System.Collections.ArrayList
    foreach( $DfsRoot in $DfsRoots ){
        
        $DfsLinks = $DfsNamespaces | Where-Object { $_.DfsRootName -eq $DfsRoot }

        
        foreach( $DfsPath in $DfsLinks.DfsPath ){
            #Todo: Eliminate DFS Module Dependency
            $DfsFolders  =  Get-DFSNFolder  -Path "$DfsPath\*" | Select-Object -ExpandProperty Path
        }
        
        foreach($DfsFolder  in $DfsFolders){
            #Todo: Eliminate DFS Module Dependency
            $DfsFolderTargets = Get-DFSNFolderTarget -Path $DfsFolder | Select-Object -ExpandProperty TargetPath
        }
        
        $DfsObject = [PSCustomObject]@{
            Name = $DfsRoot
            Servers = @($DfsLinks.Host)
            DfsPaths = @($DfsLinks.DfsPath)
            DfsFolders = @($DfsFolders)
            DfsFolderTargets  = @($DfsFolderTargets)
        }

        $null = $DfsCollection.Add($DfsObject)
    }

    New-Output -Coll $DfsCollection -Type "namespaces" -Directory $OutputDirectory
    
    $CifsPathsToCollect = New-Object System.Collections.ArrayList
    #Add the already collected DfsFolderTargets to the cifs path scan
    if($DfsCollection.DfsFolderTargets){
        foreach($ft in $DfsCollection.DfsFolderTargets){
            if( (-not [String]::IsNullOrEmpty($ft) ) -and (-not [String]::IsNullOrWhiteSpace($ft) ) ){
                $null = $CifsPathsToCollect.Add($ft)
            }
        }
    }

    #Add provided AdditionalPaths to the cifs path scan
    if($AdditionalPaths){
        foreach( $p in $AdditionalPaths ){
            if( (-not [String]::IsNullOrEmpty($p) ) -and (-not [String]::IsNullOrWhiteSpace($p) ) ){
                $null = $CifsPathsToCollect.Add($p)
            }
        }
    }

    #Scan Servers for additional  shares
    $ServersToScan = New-Object System.Collections.ArrayList

    if($DfsCollection){
        #Add Dfs Namespace Servers
        foreach($s in $DfsCollection.Servers){
            if( (-not [String]::IsNullOrEmpty($s) ) -and (-not [String]::IsNullOrWhiteSpace($s) ) ){
                $null = $ServersToScan.Add($s)
            }
        }

        #Add servers holding Dfs target folders
        foreach($tf in $DfsCollection.Targetfolders){
            if( $null -ne $tf ){
                $hostname = $tf.Split("\")[2]
                if( (-not [String]::IsNullOrEmpty($hostname) ) -and (-not [String]::IsNullOrWhiteSpace($hostname) ) ){
                    $null = $ServersToScan.Add($hostname)
                }
            }
        }
    }

    if( $Computers ){
        foreach($c in $Computers){
            if( (-not [String]::IsNullOrEmpty($c) ) -and (-not [String]::IsNullOrWhiteSpace($c) ) ){
                $null = $ServersToScan.Add($c)
            }
        }
        
    }

    Write-Information  "Scanning servers for SMB Shares"
    $ServersToScan = $ServersToScan | Sort-Object -Unique
    $CollectedShares = Invoke-NetShareEnum -Computers $ServersToScan

    foreach( $result in $CollectedShares ){
        $computer = $result.computer
        foreach( $s in $result.shares){
            $uncPath = "\\$($computer)\$($s.shi2_netname)"

            if( (-not $CifsPathsToCollect.Contains($uncPath.Replace(".$($Domain)",""))) -and (-not $CifsPathsToCollect.Contains($uncPath) ) ){
                $null = $CifsPathsToCollect.Add($uncPath)
            }
        }
    }

    $CifsPathsToCollect = $CifsPathsToCollect | Sort-Object -Unique
    $ShareCollection  = New-Object System.Collections.ArrayList
    foreach( $CifsPath in $CifsPathsToCollect ){

        try{
            Write-Debug "Querying NTFS ACL for $($CifsPath)"
            $NtfsAcl = Get-Acl -Path $CifsPath -ErrorAction Stop 
        }
        catch [System.UnauthorizedAccessException]{
            Write-Warning "Access to path  $($CifsPath) is denied."
            $NtfsAcl  = $null
        }
        catch [System.IO.FileNotFoundException]{
            Write-Warning "Path $($CifsPath) not found"
            $NtfsAcl = $null 
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            Write-Warning "Path $($CifsPath) not found"
            $NtfsAcl = $null 
        }
        catch{
            Write-Warning "Error getting ntfs acl of $($cifspath): $($_.Exception.Message)"
            Write-Error -ErrorRecord $_ -ErrorAction Continue
            $NtfsAcl = $null 
        }

        if($NtfsAcl){
            #ToDo: Optimize  query for permissions
            $FullControlAces = $NtfsAcl.Access | Where-Object { $_.FileSystemRights -eq "FullControl" }
            $ReadAces = $NtfsAcl.Access | Where-Object { $_.FileSystemRights -like "*Read*" }
            $ChangePermissionsAces = $NtfsAcl.Access | Where-Object {$_.FileSystemRights -like "*ChangePermissions*"}
            $Sddl = $NtfsAcl.Sddl

            if($Sddl){
                #get the SID of the owner, Get-ACL gives us the Owner as string instead of an IdentityReference
                #We are looking for O:S-1-*
                $SddlArray = $Sddl.Split(":")
                if( $SddlArray[0] -eq "O" -and $SddlArray -like "S-1-*"){
                    $OwnerSid = $SddlArray[1]

                    #SDDL might have letter after the SID
                    $CharArray = $OwnerSid.ToCharArray()
                    if( $CharArray[$CharArray.Count - 1 ] -notmatch "\d" ){
                        $Sid = $OwnerSid.TrimEnd( "$($CharArray[$CharArray.Count - 1 ])" )
                        $PrincipalType = Get-PrincipalTypeBySid -Identity $OwnerSid.TrimEnd( "$($CharArray[$CharArray.Count - 1 ])" )  
                    }
                    else{
                        $Sid = $OwnerSid
                        $PrincipalType = Get-PrincipalTypeBySid -Identity $OwnerSid
                    }
                    
                    $PrincipalId = Get-ObjectIdForBloodhound -Identifier $Sid -Domain $Domain

                    [PSCustomObject]$owner = @{
                        PrincipalSid = $PrincipalId
                        PrincipalType = $PrincipalType
                    }

                }
            }

            $FullControlIdentities = New-Object System.Collections.ArrayList
            if($FullControlAces){
                foreach( $Identity in $FullControlAces.IdentityReference ){
                    $Sid = Get-SidByIdentityTranslate -Identity $Identity
                    $PrincipalId = Get-ObjectIdForBloodhound -Identifier $Sid -Domain $Domain
                    [PSCustomObject]$object = @{
                        PrincipalSid = $PrincipalId
                        PrincipalType = Get-PrincipalTypeBySid -Identity $Sid
                    }

                    $null = $FullControlIdentities.Add($object)
                }
            }

            $ReadIdentities = New-Object System.Collections.ArrayList
            if($ReadAces){
                foreach( $Identity in $ReadAces.IdentityReference ){
                    $Sid = Get-SidByIdentityTranslate -Identity $Identity
                    $PrincipalId = Get-ObjectIdForBloodhound -Identifier $Sid -Domain $Domain

                    [PSCustomObject]$object = @{
                        PrincipalSid = $PrincipalId
                        PrincipalType = Get-PrincipalTypeBySid -Identity $Sid
                    }
                    $null = $ReadIdentities.Add($object)
                }
            }

            $ChangePermissionsIdentities = New-Object System.Collections.ArrayList
            if($ChangePermissionsAces){
                foreach( $Identity in $ChangePermissionsAces.IdentityReference ){
                    $Sid = Get-SidByIdentityTranslate -Identity $Identity
                    $PrincipalId = Get-ObjectIdForBloodhound -Identifier $Sid -Domain $Domain

                    [PSCustomObject]$object = @{
                        PrincipalSid = $PrincipalId
                        PrincipalType = Get-PrincipalTypeBySid -Identity $Sid
                    }
                    
                    $null = $ChangePermissionsIdentities.Add($object)
                }
            }
        }

        $cifshost = $CifsPath.Split("\")[2]

        if( $cifshost.split(".").count -gt 0 ){
            #name already contains domain
        }
        else{
            Write-Debug "Adding domain to cifshost $($cifshost)"
            $cifshost = "$($cifshost).$($Domain)"
        }

        try{
            $identityname = "$($Domain)\$($cifshost.Replace(".$domain",''))$" 
            $cifshostidentity = New-Object System.Security.Principal.ntaccount($identityname)
            $cifshostsid = $cifshostidentity.Translate([system.security.principal.securityidentifier]).value
        }
        catch{
            Write-Warning "Error translating SID for $($identityname): $($_.Exception.Message)"
            Write-Error -ErrorRecord $_ -ErrorAction Continue
            $cifshostsid = "N/A"
        }
        $ShareObject = [PSCustomObject]@{
            name = "$($cifspath.split("\")[$cifspath.split("\").length - 1])"
            cifspath  =  $CifsPath
            cifshost = $cifshost
            objectid = "$($domain).$cifshostsid.$($cifspath.split("\")[$cifspath.split("\").length - 1])"
            domain = $Domain
            cifshostsid = $cifshostsid
            fullcontrol  = @($FullControlIdentities)
            read =  @($ReadIdentities)
            changepermissions = @($ChangePermissionsIdentities)
            owner = $owner
        }

        $null = $ShareCollection.Add($ShareObject)
    }
    New-Output -Coll $ShareCollection -Type "fileshares" -Directory $OutputDirectory
    
}