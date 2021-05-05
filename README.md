# quantum_resistant_KEM
Python scripts for quantum resistant key passage and file transfer.

This is a class project for CS_GY 6903 at NYU Tandon School of Engineering. **IT SHOULD NOT BE USED TO TRANSFER SENSITIVE INFORMATION AT THIS TIME**

The scripts are based on the Open Quantum Safe library and its python wrapper: https://openquantumsafe.org/.  The LibOQS library is available on github at https://github.com/open-quantum-safe/liboqs.

Installation:
1. Install OQS by following the directions on https://github.com/open-quantum-safe/liboqs.
2. Install the OQS python bindings by following the directions on https://github.com/open-quantum-safe/liboqs-python.
3. Download the scripts.  

Use:
-help:    show options/examples
-h:       set host
-p:       set port
-a:       set algorithms
-o:       set output file name
-s:       set server status
-f:       specify file to transfer (file share only)

Use the argument followed by the value.  For example: 
python3 key_share.py -s -p 1337 -a Kyber1024 
will start a server on port 1337 that uses the Kyber1024 algorithm.

To generate shared keys on two machines, run two copies of this script, one on each machine.  Set one as the server and connect with the other by directing it to the host/port the server is listening on.  The shared key will generated on each machine and written out to a file (file name can be specified with -o).

To transfer a file use file_share.  Set one to server with -s.  You can also specify the output filename with -o. On the other machine run the script and specify the file you wish to transfer with -f. 

Algorithms: 
This script uses the OQS Library, so algorithms and algorithm names should match OQS.  This has been tested with a variety of Kyber and NTRU variants.
Tested variants include: Kyber512, Kyber 768, Kyber1024, NTRU-HPS-2048-509, and NTRU-HPS-2048-677.

Additional files:
Additionally, this repository contains the export of a dockerfile using openSSH with quantum resistant KEMS and some simple benchmarks of the performance python scripts above. 
Performance was measured by testing six algorithms three times each and logging the time for the client and server.  Those were averaged to return single values, though the full data is available in the attached performance spreadsheet.
