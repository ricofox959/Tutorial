# MBAM Bitlocker and TCG logs from Event logs and other important values

The original is based on a script by Tanner Slayton 
https://github.com/tslayton/Ignite_2016

I added support for Windows 7.

The XML filters require the requested compenets be present like MBAM. if MBAM logs are not present the XML will fail.

Future plan:
  CMTrace style logging.
  Convert FilteredTCGLog from HEX to ASCII
