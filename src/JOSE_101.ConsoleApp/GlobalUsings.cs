global using System.Text;
global using System.Text.Json;
global using System.Security.Cryptography;
global using Jose;
global using Spectre.Console;
global using Spectre.Console.Rendering;
global using JOSE_101.Core.Jws;
global using JOSE_101.Core.Jwe;
global using JOSE_101.Core.Nested;
global using JOSE_101.Core.Inspection;
global using JOSE_101.ConsoleApp;
global using JOSE_101.ConsoleApp.Actions;

// jose-jwt also ships a Base64Url type, so this picks the BCL one for the whole project.
global using Base64Url = System.Buffers.Text.Base64Url;
