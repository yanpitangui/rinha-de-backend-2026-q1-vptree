using System.Runtime.InteropServices;

namespace FraudApi.Shared;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe struct Block
{
    public fixed short D0[64];
    public fixed short D1[64];
    public fixed short D2[64];
    public fixed short D3[64];
    public fixed short D4[64];
    public fixed short D5[64];
    public fixed short D6[64];
    public fixed short D7[64];
    public fixed short D8[64];
    public fixed short D9[64];
    public fixed short D10[64];
    public fixed short D11[64];
    public fixed short D12[64];
    public fixed short D13[64];
}