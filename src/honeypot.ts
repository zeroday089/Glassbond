export const honeypotRoutes = ["/wp-admin", "/phpmyadmin", "/admin-panel", "/.git", "/.env", "/xmlrpc.php"];

export function isHoneypotPath(path: string): boolean {
  return honeypotRoutes.some((route) => path === route || path.startsWith(`${route}/`));
}
