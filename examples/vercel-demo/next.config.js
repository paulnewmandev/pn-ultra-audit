module.exports = {
  typescript: { ignoreBuildErrors: true },
  productionBrowserSourceMaps: true,
  images: { remotePatterns: [{ protocol: 'https', hostname: '**' }] },
};
