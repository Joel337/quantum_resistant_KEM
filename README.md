# quantum_resistant_KEM
Simple python script for quantum resistant key passage.

This is a class project for CS_GY 6903 at NYU Tandon School of Engineering. 

The script is based on the Open Quantum Safe library and its python wrapper: https://openquantumsafe.org/.  The LibOQS library is available on github at https://github.com/open-quantum-safe/liboqs.

Installation:
1. Install OQS by following the directions on https://github.com/open-quantum-safe/liboqs.
2. Install the OQS python bindings by following the directions on https://github.com/open-quantum-safe/liboqs-python.
3. Download the script.  

Use:
-help:    show options/examples
-h:       set host
-p:       set port
-a:       set algorithms
-o:       set output file name
-s:       set server status

Use the argument followed by the value.  For example: 
python3 key_share.py -s -p 1337 -a Kyber1024 
will start a server on port 1337 that uses the Kyber1024 algorithm.

To generate shared keys on two machines, run two copies of this script, one on each machine.  Set one as the server and connect with the other by directing it to the host/port the server is listening on.  The shared key will generated on each machine and written out to a file (file name can be specified with -o).

Algorithms: 
This script uses the OQS Library, so algorithms and algorithm names should match OQS.  This has been tested with a variety of Kyber and NTRU variants.
Tested variants include: Kyber512, Kyber 768, Kyber1024, NTRU-HPS-2048-509, and NTRU-HPS-2048-677.
