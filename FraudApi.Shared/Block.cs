using System.Runtime.InteropServices;

namespace FraudApi.Shared;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe struct Block
{
    public fixed short D0[8];
    public fixed short D1[8];
    public fixed short D2[8];
    public fixed short D3[8];
    public fixed short D4[8];
    public fixed short D5[8];
    public fixed short D6[8];
    public fixed short D7[8];
    public fixed short D8[8];
    public fixed short D9[8];
    public fixed short D10[8];
    public fixed short D11[8];
    public fixed short D12[8];
    public fixed short D13[8];
}
