import { Canister, ic, query, text,int32, update, Void, Principal, Record, Vec, StableBTreeMap , bool, nat, AzleInt32} from 'azle';

// use hardcoded admin for now
let admin : text = "2vxsx-fae";
let threshold : int32 = 100;    

const Entry = Record({
    //list of who submitted the report
    reporter: Vec(Principal),
    weight : int32
});

// user reputation, the higher the better, user report will be based weighted on this
let reputation = StableBTreeMap(Principal, int32 ,0);
//base reputation is 1

// list of malicious contract
let contract = StableBTreeMap(Principal, Entry, 1);

//contract
export default Canister({

    // report a contract
    report: update([Principal], int32, (reported) => {
        if(contract.containsKey(reported)) {
            let entry = contract.get(reported).Some;
            let newWeight : int32 = reputation.containsKey(ic.caller()) ? entry.weight + reputation.get(ic.caller()).Some : entry.weight + 1;
            const updatedUser: typeof Entry = {
                reporter: [...entry.reporter, ic.caller()],
                weight: newWeight 
            }
            contract.insert(reported, updatedUser);
            return newWeight;
        } else {
            let newWeight : int32 = reputation.containsKey(ic.caller()) ? reputation.get(ic.caller()).Some : 1;
            const updatedUser: typeof Entry = {
                reporter: [ic.caller()],
                weight: newWeight
            }
            contract.insert(reported, updatedUser);
            return newWeight;
        }

    }),

    //getter function for reputation
    getReputation: query([Principal], int32, (target) => {
        if(reputation.containsKey(target)) {
            return reputation.get(target).Some;
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
            return reputation.get(ic.caller()).Some;
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

    reccomend: update([Principal], int32, (target) => {
        if(reputation.containsKey(ic.caller())) {
            //if target already has reputation, add 1 to their reputation
            if(reputation.containsKey(target)) {
                let entry = reputation.get(ic.caller()).Some;
                reputation.insert(target, entry + 1);
                return entry + 1;
            } 
            //if target doesn't have reputation, give them 2 as init value
            else {
                reputation.insert(target, 2);
                return 2;
            }
        }
        //return 0 if you/sender don't have reputation 
        throw new Error("You don't have reputation");
    }),

    //admin function
    //set weight
    setWeight: update([Principal, int32], int32, (target, weight) => {
        if(ic.caller().toText() == admin) {
            if(contract.containsKey(target)) {
                let entry = contract.get(target).Some;
                const updatedUser: typeof Entry = {
                    reporter: entry.reporter,
                    weight: weight
                }
                contract.insert(target, updatedUser);
                return weight;
            } else {
                const updatedUser: typeof Entry = {
                    reporter: [],
                    weight: weight
                }
                contract.insert(target, updatedUser);
                return weight;
            }
        }
        throw new Error("You are not admin");
    }),

    //set reputation
    setReputation: update([Principal, int32], int32, (target, rep) => {
        if(ic.caller().toText() == admin) {
            reputation.insert(target, rep);
            return rep;
        }
        throw new Error("You are not admin");
    }),

    //set threshold
    setThreshold: update([int32], int32, (thres) => {
        if(ic.caller().toText() == admin) {
            threshold = thres;
            return thres;
        }
        throw new Error("You are not admin");
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
