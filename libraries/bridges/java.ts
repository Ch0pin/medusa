import Java from 'frida-java-bridge';
(globalThis as unknown as { Java: typeof Java }).Java = Java;
