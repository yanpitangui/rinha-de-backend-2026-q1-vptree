using System.Runtime.InteropServices;

namespace FraudApi.Shared;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe struct Block
{
    public fixed short D0[16];
    public fixed short D1[16];
    public fixed short D2[16];
    public fixed short D3[16];
    public fixed short D4[16];
    public fixed short D5[16];
    public fixed short D6[16];
    public fixed short D7[16];
    public fixed short D8[16];
    public fixed short D9[16];
    public fixed short D10[16];
    public fixed short D11[16];
    public fixed short D12[16];
    public fixed short D13[16];
}
