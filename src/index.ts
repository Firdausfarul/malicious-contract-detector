import { Canister, ic, query, text,int32, update, Void, Principal, Record, Vec, StableBTreeMap , bool, init, nat, AzleInt32, Ok, Result, Err} from 'azle';

// use hardcoded admin for now
let admin : text = "2vxsx-fae";
let threshold : int32 = 100;    

const Entry = Record({
    //list of who submitted the report
    reporter: Vec(Principal),
    weight : int32
});
const EntryReputation = Record({
    //list of who submitted the report
    principals: Vec(Principal),
    reputation : int32
});

// user reputation, the higher the better, user report will be based weighted on this
let reputation = StableBTreeMap(Principal, EntryReputation ,0);
//base reputation is 1

// list of malicious contract
let contract = StableBTreeMap(Principal, Entry, 1);

//contract
export default Canister({

    init: init([], () => {
        admin = ic.caller().toString();
    }),

    // report a contract
    report: update([Principal], Result(int32, text), (reported) => {
        if(contract.containsKey(reported)) {
            let entry: typeof Entry = contract.get(reported).Some;
            // ensures a principal can only report another user once
            if (entry.reporter.findIndex(reporter => reporter.toText() === ic.caller().toText()) >= 0){
                return Err("You have already reported the user")
            }
            let newWeight : int32 = reputation.containsKey(ic.caller()) ? entry.weight + reputation.get(ic.caller()).Some.reputation : entry.weight + 1;
            const updatedUser: typeof Entry = {
                reporter: [...entry.reporter, ic.caller()],
                weight: newWeight 
            }
            contract.insert(reported, updatedUser);
            return Ok(newWeight);
        } else {
            let newWeight : int32 = reputation.containsKey(ic.caller()) ? reputation.get(ic.caller()).Some.reputation : 1;
            const updatedUser: typeof Entry = {
                reporter: [ic.caller()],
                weight: newWeight
            }
            contract.insert(reported, updatedUser);
            return Ok(newWeight);
        }

    }),

    //getter function for reputation
    getReputation: query([Principal], int32, (target) => {
        if(reputation.containsKey(target)) {
            return reputation.get(target).Some.reputation;
        }
        return 1;
    }),

    //is the contract malicious?
    isMalicious: query([Principal], bool, (target) => {
        if(contract.containsKey(target)) {
            let entry = contract.get(target).Some;
            if(entry.weight > threshold) {
                return true;
            }
        }
        return false;
    }),

    //get the malicious weight of a contract
    getWeight: query([Principal], int32, (target) => {
        if(contract.containsKey(target)) {
            let entry = contract.get(target).Some;
            return entry.weight;
        }
        return 0;
    }),

    //get your reputation
    yourReputation: query([], int32, () => {
        if(reputation.containsKey(ic.caller())) {
            return reputation.get(ic.caller()).Some.reputation;
        }
        return 1;
    }),

    //helper function to get your principal
    yourPrincipal: query([], Principal, () => {
        return ic.caller();
    }),

    //helper function to get admin
    getAdmin: query([], text, () => {
        return admin;
    }),

    recommend: update([Principal], Result(int32, text), (target) => {
        if(reputation.containsKey(ic.caller())) {
            //if target already has reputation, add 1 to their reputation
            if(reputation.containsKey(target)) {
                let entry : typeof EntryReputation = reputation.get(target).Some;
                // ensures a principal can only recommend another user once
                if (entry.principals.findIndex(principal => principal.toText() === ic.caller().toText()) >= 0){
                    return Err("You have already recommended the user")
                }
                let updatedEntry: typeof EntryReputation = {
                    principals: [...entry.principals, ic.caller()],
                    reputation: entry.reputation + 1
                }
                reputation.insert(target, updatedEntry);
                return Ok(updatedEntry.reputation);
            } 
            //if target doesn't have reputation, give them 2 as init value
            else {
                let entry: typeof EntryReputation = {
                    principals: [ic.caller()],
                    reputation: 2
                }
                reputation.insert(target, entry);
                return Ok(entry.reputation);
            }
        }
        //return 0 if you/sender don't have reputation 
        return Err("You don't have reputation");
    }),

    //admin function
    //set weight
    setWeight: update([Principal, int32], Result(int32, text), (target, weight) => {
        if(ic.caller().toText() == admin) {
            if(contract.containsKey(target)) {
                let entry = contract.get(target).Some;
                const updatedUser: typeof Entry = {
                    reporter: entry.reporter,
                    weight: weight
                }
                contract.insert(target, updatedUser);
                return Ok(weight);
            } else {
                const updatedUser: typeof Entry = {
                    reporter: [],
                    weight: weight
                }
                contract.insert(target, updatedUser);
                return Ok(weight);
            }
        }
        return Err("You are not admin");
    }),

    //set reputation
    setReputation: update([Principal, int32], Result(int32, text), (target, rep) => {
        if(ic.caller().toText() == admin) {
            let entry : typeof EntryReputation;
            if (reputation.containsKey(target)){
                let fetchedEntry : typeof EntryReputation = reputation.get(target).Some;
                entry = {
                    principals: [...fetchedEntry.principals, ic.caller()],
                    reputation: rep
                }
            }else{
                entry = {
                    principals: [ic.caller()],
                    reputation: rep
                }
            }
            reputation.insert(target, entry);
            return Ok(rep);
        }
        return Err("You are not admin");
    }),

    //set threshold
    setThreshold: update([int32], Result(int32, text), (thres) => {
        if(ic.caller().toText() == admin) {
            threshold = thres;
            return Ok(thres);
        }
        return Err("You are not admin");
    }),

    //get all malicious contract
    getAllMalicious: query([], Vec(Principal), () => {
        return contract.keys();
    }),

    //get all user that have reputation
    getAllUser: query([], Vec(Principal), () => {
        return reputation.keys();
    }),

    isAdmin: query([], bool, () => {
        return ic.caller().toText() == admin;
    }),

});
