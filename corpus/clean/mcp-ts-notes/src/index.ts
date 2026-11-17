import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { appendFile } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";

const NOTES_DIR = path.resolve(process.env.NOTES_DIR ?? "./notes");
const server = new McpServer({ name: "scoped-notes", version: "1.2.0" });

server.tool("append_note", { title: z.string().regex(/^[\w-]{1,64}$/), text: z.string().max(4000) },
  async ({ title, text }) => {
    const file = path.join(NOTES_DIR, `${title}.md`);
    if (!file.startsWith(NOTES_DIR + path.sep)) throw new Error("path escapes notes dir");
    await appendFile(file, text + "\n");
    return { content: [{ type: "text", text: `appended to ${title}.md` }] };
  });

await server.connect(new StdioServerTransport());
