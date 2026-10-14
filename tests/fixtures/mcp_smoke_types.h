typedef struct mcp_pkt_hdr {
    unsigned short len;
    unsigned char kind;
    unsigned char flags;
} mcp_pkt_hdr;

enum mcp_pkt_kind { MCP_PK_A = 1, MCP_PK_B = 2 };
