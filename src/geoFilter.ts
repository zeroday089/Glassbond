import type { GlassBondRequest, GeoLookup } from "./types.js";

export async function isGeoBlocked(request: GlassBondRequest, blockedCountries: string[], lookup?: GeoLookup): Promise<boolean> {
  if (!lookup || blockedCountries.length === 0) return false;
  const country = await lookup(request.ip, request);
  return country ? blockedCountries.map((value) => value.toUpperCase()).includes(country.toUpperCase()) : false;
}
