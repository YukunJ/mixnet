# 15-441/15-641 Project 1: Mixnet

## Requirements

This project is designed to run on Linux. It was tested on Ubuntu 20.04.2 LTS, but you may get away by using other distributions.

## Building

You need `cmake` and `sctp` to build the project. On Ubuntu, you can install them with:
```bash
sudo apt install cmake libsctp-dev
```

To build the project, in the root directory, run:
```bash
mkdir build
cd build
cmake ..
make
```

From now on you can always build the project by going to the `build` directory and running `make`.

## Running

Mixnet is test-driven. You can find some examples of these tests under the `testing` directory. For instance, cp1/test_line_easy.cpp demonstrates how to create a line topology with two nodes, 'subscribe' to packet data from one of them, and send a FLOOD packet from one to the other.

You can run mixnet in two modes: an 'autotester' mode, which we will be using to grade your implementation, and 'manual' mode, which you can use to debug your implementation on either a single machine (using one process per mixnet node) or a cluster of machines. You will also use the second mode to perform experiments on AWS (please see the handout for details).

To run in autotester mode, `cd` into the build directory and run:
```
./bin/test_line_easy -a # '-a' toggles the autotester
```
At the end, it should produce output indicating whether your implementation passed or failed that particular test-case.

You can also run the same test in 'manual' mode. For the test_line_easy example, you will need three terminal windows open: one for each of the mixnet nodes, and one for the 'orchestrator', which bootstraps the topology, sets up connections, coordinates actions, etc. In general, you will need (n + 1) terminals, where n is the number of mixnet nodes in the test topology. First, start the orchestrator:
```
./bin/test_line_easy # Note that '-a' is missing
```

You should see output that looks like this: ```[Orchestrator] Started listening on port 9107 with session nonce 39239```. Note both the port (it's always 9107) the server is running on, as well as the nonce (changes every run). Next, type the following commands in the other two terminals (one in each):
```
./bin/node 127.0.0.1 9107 0 {nonce}
./bin/node 127.0.0.1 9107 1 {nonce}
```
The format is as follows: ./node {server_ip} {server_port} {node_id} {nonce}. The node IDs correspond to indices in the 'topology' vector for the testcase; for this example, the node with ID 0 will be assigned a mixnet address of 0, and the other with a mixnet address of 1 (see 'mixaddrs' in test_line_easy.cpp). Please refer to the other test-cases (as well as the test API in harness/orchestrator.h) for more examples and detailed usage.

The entry-point to your code is the `run_node()` function in mixnet/node.c. For details, please refer to the handout. Good luck!
