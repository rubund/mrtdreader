mrtdreader
==========

Machine-readable travel documents such as passports nowadays usually contain
an RFID chip for storing various data. This library provides useful
functions for reading out the data from these documents. This version of the
library supports the Basic Access Control (BAC). It uses several cryptographic
functions from either libgcrypt or libtomcrypt (depending on compile-time
options) in order to do the necessary decryption of the content of the MRTDs.
The key for the BAC-scheme is derived from the Machine-readable zone (MRZ)
which is printed on the MRTD.
 
The library depends on libnfc for the hardware interaction and only devices
supported by libnfc will therefore work.


Build instruction
-----------------
- cmake .
- make
- sudo make install
- sudo ldconfig


Usage
------------
There is a tool called *mrtdreader* using the library which can be run like
this:

- mrtdreader &lt;MRZ&gt;

MRZ is the bottom line on the machine-readable travel document.

Content of MRTDs
----------------

The following files may be present in the MRTD:

* EF.DG1  - 0101 - MRZ
* EF.DG2  - 0102 - Face
* EF.DG3  - 0103 - Fingerprint
* EF.DG4  - 0104 - Iris
* EF.DG5  - 0105 - Portrait
* EF.DG6  - 0106 - RFU
* EF.DG7  - 0107 - Displayed signature
* EF.DG8  - 0108 - Data features
* EF.DG9  - 0109 - Structure features
* EF.DG10 - 010A - Substance features
* EF.DG11 - 010B - Additional personal details
* EF.DG12 - 010C - Additional document features
* EF.DG13 - 010D - Optional details
* EF.DG14 - 010E - EAC
* EF.DG15 - 010F - AA Public key
* EF.DG16 - 0110 - Persons to notify
* EF.CA   - 011C - 
* EF.SOD  - 011D - Security object data - hash values
* EF.COM  - 011E - EF.COM

The example program *mrtdreader* reads out the MRZ, the facial image, the EF.COM
file and the EF.SOD file.
