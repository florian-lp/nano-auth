import { useEffect, useState } from "react";
import { SupportedOAuthProviders } from "./oauth";
import { readCookies } from "./lib";

export function useLastUsed() {
    const [lastUsed, setLastUsed] = useState<SupportedOAuthProviders | null>(null);

    useEffect(() => {
        const cookies = readCookies();
        const lastUsed = cookies['nano-last-used'];

        if (lastUsed) setLastUsed(lastUsed as any);
    }, []);

    return lastUsed;
}