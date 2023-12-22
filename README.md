# Malicious Contract Detector

## Overview
This contract is basically a on-chain reputation system. It allows users to report malicious contracts and automatically flag if enough account report the same contract. The report is weighted by the reputation of the reporter. each user can reccomend each other to increase their reputation. A contract is considered malicious if enough users report it and the reputation of the reporters is high enough. The reputation of a user is the sum of the reputation of the users that reccomended him. Any ICP account have a reputation of 1 by default. However admin have escalated privilige and can set the reputation of any account. The admin can also set the threshold for a contract to be considered malicious. 


## Usage
The method name is pretty self explanatory.

## deploy
```
    dfx deploy
```
