module.exports = {
  networks: {
    development: {
      host: "127.0.0.1", // Localhost (default: none)
      port: 7545,        // Port (default: none)
      network_id: "*",   // Match any network id (default: none)
    },
  },

  // Configure your compilers
  // compilers: {
  //   solc: {
  //     version: "^0.8.0", // Fetch exact version from solc-bin
  //     settings: {
  //       optimizer: {
  //         enabled: true,
  //         runs: 200,
  //       },
  //     },
  //   },
  // },
};
