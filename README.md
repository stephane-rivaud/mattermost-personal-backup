# AI Assistant Scaffolding Project

This project serves as a central repository for maintaining tools, documentation, and configurations that enable AI assistants to interact with your macOS system effectively.

## Purpose

This scaffolding provides:
- MCP (Model Context Protocol) server configurations
- Documentation for AI assistant setup and troubleshooting
- Tools and utilities for system interaction
- Knowledge base for other AI assistants to query

## Project Structure

```
.
├── README.md                          # This file
├── docs/                              # Documentation directory
│   ├── mcp-servers/                   # MCP server documentation
│   │   └── apple-mcp-installation.md  # Apple MCP server setup guide
│   └── troubleshooting/               # Troubleshooting guides
└── .git/                              # Git repository
```

## MCP Servers Configured

### Apple MCP Server
Provides access to macOS applications including:
- **Messages**: Send, read, and schedule messages
- **Notes**: Create, search, and manage notes
- **Contacts**: Find and retrieve contact information
- **Mail**: Send emails, search, schedule, and check unread counts
- **Reminders**: Create, search, and manage reminders
- **Calendar**: Create events, search, and list upcoming events
- **Maps**: Search locations, save favorites, get directions, create guides

**Installation Date**: October 19, 2025  
**Documentation**: See `docs/mcp-servers/apple-mcp-installation.md`

## Quick Start

### For AI Assistants
When interacting with this system, you can:
1. Read documentation in the `docs/` directory for setup procedures
2. Access MCP servers configured in `~/.codeium/windsurf/mcp_config.json`
3. Reference troubleshooting guides for common issues

### For Humans
To add or modify MCP servers:
1. Edit `~/.codeium/windsurf/mcp_config.json`
2. Restart Windsurf IDE
3. Click the refresh button in the Cascade MCP plugins panel
4. Document any changes in the appropriate `docs/` subdirectory

## Configuration Files

- **MCP Config**: `~/.codeium/windsurf/mcp_config.json`
- **Backup**: `~/.codeium/windsurf/mcp_config.json.backup`

## Contributing

When adding new tools or configurations:
1. Document the installation process thoroughly
2. Include troubleshooting steps if issues were encountered
3. Update this README with the new capability
4. Commit changes with descriptive messages

## Resources

- [Windsurf MCP Documentation](https://docs.windsurf.com/windsurf/cascade/mcp)
- [Apple MCP GitHub Repository](https://github.com/supermemoryai/apple-mcp)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
