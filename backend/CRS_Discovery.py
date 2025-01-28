import pm4py
import pandas as pd
import numpy as np
import re
from concurrent.futures import ThreadPoolExecutor
from math import ceil
import os
from multiprocessing import Pool, cpu_count
from itertools import combinations


class LocalNet:
    def __init__(self, P_L, T_L, F_L, M_L, R_L):
            self.P_L = frozenset(P_L)  # Places
            self.T_L = frozenset(T_L)  # Internal transitions
            self.F_L = frozenset(F_L)  # Flow relations
            self.M_L = frozenset(M_L)  # Message transitions
            self.R_L = frozenset(R_L)  # Communication places

    def __hash__(self):
        return hash((self.P_L, self.T_L, self.F_L, self.M_L, self.R_L))
    
    def __eq__(self, other):
        if not isinstance(other, LocalNet):
            return False
        return (self.P_L == other.P_L and 
                self.T_L == other.T_L and 
                self.F_L == other.F_L and 
                self.M_L == other.M_L and 
                self.R_L == other.R_L)
    
class CreEvent:
    def __init__(self, df, isMsg):
        self.id = df["event_id"]
        self.resId = df["res_id"]
        self.context = df["context"]
        self.h_ctx = df["h_ctx"] if isMsg else None
        self.sender = df["sender"] if isMsg else None
        self.receiver = df["receiver"] if isMsg else None

    def __hash__(self):
        return hash((self.resId, self.context, self.h_ctx, self.sender, self.receiver))

    


def test_plans():
    #plan = pm4py.read.read_xes("C:\\Users\\sofyv\\Documents\\Universität\\WiSe24_25\\Praktikum\\processDiscovery\\backend\\default_discovery_plans\\FP_Log.xes")
    plan = pm4py.read.read_xes("C:\\Users\\sofyv\\Documents\\Universität\\WiSe24_25\\Praktikum\\processDiscovery\\backend\\default_discovery_plans\\IP-8_init_log.xes")
    #plan2 = pm4py.read.read_xes("C:\\Users\\sofyv\\Documents\\Universität\\WiSe24_25\\Praktikum\\processDiscovery\\backend\\default_discovery_plans\\RL-1.xes")
    plan_update = plan.drop(columns=["time:timestamp"])
    plan_update.to_csv("IP8_Log.csv", index=False) 
    # plan_update1 = plan1.drop(columns=["time:timestamp"])
    # plan_update1.to_csv("output3.csv", index=False) 
    # plan_update2 = plan2.drop(columns=["time:timestamp"])
    # plan_update2.to_csv("output4.csv", index=False) 

    # pm4py.discovery.discover_petri_net_alpha()
    
    #print(plan.columns)

''' 
Step 1: Detect the structure of different event logs and enric the logs so that they have following format:

Communciation Ressource Event (CRE): <event_id, res_id, context, h_ctxt, source_uri, dest_uri>
* event_id: ID of event in Res.
* res_id: ID of Res. (globally unique)
* context: case_ID of process
* h_ctx: context of Res. that invoked logging Res. (this Res.) 
* source_uri: communication source Res. uri address (e.g /Service_A/sub_Service_1/)
* dest_uri: communication destination Res. uri address 

CRE can be a communication event or a local Event -> Local event has null value for h_ctx, source_uri, dest_uri

A Res. r that invokes another Res s will not have a h_ctx. The log of Res. s will contain the h_ctx and it equals the context of Res. r

Return: A Ressource Event Log RL, with events that follow the required structure
'''

def add_msg_context(event_log, msgColName, activityColName, resColName):
     
        filtered_log = event_log.dropna(subset=[msgColName])
        
        messages_grouped = (
            filtered_log.groupby(msgColName)
            .agg(
                h_ctx=(activityColName, "first"),
                sender=(resColName, lambda x: x.tolist()[0] if len(x) > 0 else None),
                receiver=(resColName, lambda x: x.tolist()[1] if len(x) > 1 else None)
            )
            .reset_index()
        )

        merged_log = pd.merge(event_log, messages_grouped, "left" ,on=msgColName)
        merged_log.loc[merged_log[resColName] == merged_log["sender"], "h_ctx"] = None

        return merged_log



def modify_Logs(event_log): 
    log_structure = -1
    columns= event_log.columns
    if(columns.str.contains('msgInstanceId', case=False).any() | columns.str.contains('msgInstanceID', case=False).any()):
        log_structure = 1
    elif (columns.str.contains('Message:Sent', case=False).any() and columns.str.contains('Message:Rec', case=False).any()):
        log_structure = 2
    else:
        log_structure = 3

    modified_log = pd.DataFrame()

    match log_structure: 
        case 1:
            column_name = "msgInstanceId" if columns.str.contains('msgInstanceId', case=True).any() else "msgInstanceID" 
            merged_log = add_msg_context(event_log,column_name, "concept:name","org:group")
            merged_log['event_id'] = range(1, len(merged_log) + 1)

            modified_log[["case_id","event_id","res_id","context","h_ctx","sender","receiver"]] = merged_log[['case:concept:name', 'event_id', 'org:group', "concept:name","h_ctx","sender","receiver"]]

        case 2:
        #TODO WICHTIG: Überlge, ob man für message wie m1,m2,m3 die selbe eventID nehmen soll oder für jede eine einzelne, 
        # weil eig. werden die drei messages im selben event gesendet
            df = event_log
            df.loc[df["Message:Rec"].notna(), "Message:Sent"] = df["Message:Rec"]

            df['Message:Sent'] = df['Message:Sent'].apply(lambda x: str(x).split(',') if pd.notna(x) else [None])
            df_expanded = df.explode('Message:Sent', ignore_index=True)
            df_expanded['Message:Sent'] = df_expanded['Message:Sent'].apply(lambda x: pd.NA if x == 'null' else x)
            df_expanded['Message:Sent'] = df_expanded.apply(lambda row: f"{row['Message:Sent']}_{row['case:concept:name']}" if pd.notna(row['Message:Sent']) else row['Message:Sent'], axis=1)
            
            merged_log = add_msg_context(df_expanded,"Message:Sent", "concept:name","org:resource")
            merged_log['event_id'] = range(1, len(merged_log) + 1)
            modified_log[["case_id","event_id","res_id","context","h_ctx","sender","receiver"]] = merged_log[['case:concept:name', 'event_id', 'org:resource', "concept:name","h_ctx","sender","receiver"]]
        case 3:
            print("TBD")
            event_log['event_id'] = range(1, len(event_log) + 1)
            event_log.loc[event_log["concept:name"].str.contains(r'[?!]'), "msgInstanceId"] = (
                event_log.loc[event_log["concept:name"].str.contains(r'[?!]'), "concept:name"].str.extract(r'(.*?)[?!]', expand=False) +
                "_" +
                event_log.loc[event_log["concept:name"].str.contains(r'[?!]'), "case:concept:name"]
            )

            print(event_log.columns)
            merged_log = add_msg_context(event_log,"msgInstanceId", "concept:name","org:resource")
            modified_log[["case_id","event_id","res_id","context","h_ctx","sender","receiver"]] = merged_log[['case:concept:name', 'event_id', 'org:resource', "concept:name","h_ctx","sender","receiver"]]
            modified_log.to_excel("IP_Output.xlsx", index=False)
        case _:
            print("Could not categorize log strcuture")

    return modified_log

            	
def split_log_by_case(event_log, n):
    grouped = event_log.groupby('case:concept:name')
    cases = list(grouped)
    chunk_size = len(cases) // n
    chunks = [pd.concat([x[1] for x in cases[i:i + chunk_size]], ignore_index=True) for i in range(0, len(cases), chunk_size)]
    return chunks

def create_REL(event_log):
    final_df = pd.DataFrame
    if event_log["case:concept:name"].nunique() > 10000: 
        chunks = split_log_by_case(event_log, 6)
        with Pool(processes=6) as pool:
            results = pool.map(modify_Logs, chunks)
        final_df = pd.concat(results, ignore_index=True)
    else: 
        final_df = modify_Logs(event_log)
    return final_df


''' 
Step 4: Mine_Local_Process

* Alternate Alpha miner so it also mines invokation processes 
'''
def local_invocation(log):
    filtered_log = log.loc[log["sender"].notnull() & log["receiver"].notnull(), :]
    grouped_log = filtered_log.groupby(["case_id"])
    invocation_set = set()
    for _, group in grouped_log:
        for i in range(len(group) - 1):
            if pd.isna(group.iloc[i]["h_ctx"]):
                A = group.iloc[i]
                sender = group.iloc[i]["sender"]

                subframe = group.iloc[i:]
                matching_rows = subframe[subframe["h_ctx"].notnull() & (subframe["receiver"] == sender)]

                if not matching_rows.empty:
                    B = matching_rows.iloc[0]["context"]
                    invocation_set.add((A, B))

    return invocation_set

def eliminate_duplicates(XL):
    """
    Build YL by eliminating duplicates and non-maximal pairs (step 8)
    Now works with tuples instead of frozensets
    """
    YL = set()
    
    for (A, B) in XL:
        # Convert tuples to sets for subset comparison
        A_set = set(A)
        B_set = set(B)
        
        # Check if there exists a larger pair that contains this one
        is_maximal = True
        for (A2, B2) in XL:
            A2_set = set(A2)
            B2_set = set(B2)
            if (A, B) != (A2, B2) and A_set.issubset(A2_set) and B_set.issubset(B2_set):
                is_maximal = False
                break
        
        if is_maximal:
            YL.add((A, B))
    
    return YL

def build_causal_relations(internal_act, message_trans, grouped_log):
    XL = set()
    
    def directly_follows(a, b, group):
        for i in range(len(group) - 1):
            if group.iloc[i]["context"] == a and group.iloc[i + 1]["context"] == b:
                return True
        return False
    
    def get_subsets(activities):
        result = []
        for i in range(1, len(activities) + 1):
            for combo in combinations(activities, i):
                result.append(set(combo))
        return result
    
    all_activities = internal_act.union(message_trans)
    subsets = get_subsets(all_activities)
    
    for A in subsets:
        for B in subsets:

            if not A or not B:
                continue
                
            if A.issubset(internal_act) and B.issubset(internal_act):
                valid = True
                for a in A:
                    for b in B:
                        follows = False
                        for _, group in grouped_log:
                            if directly_follows(a, b, group):
                                follows = True
                                break
                        if not follows:
                            valid = False
                            break
                    if not valid:
                        break
                
                if valid and len(A) == len(set(A)) and len(B) == len(set(B)):
                     XL.add((tuple(sorted(A)), tuple(sorted(B))))
            
            # Condition 2: Mixed internal and message transitions
            elif ((A.issubset(internal_act) and B.issubset(message_trans)) or
                (A.issubset(message_trans) and B.issubset(internal_act))):
                 XL.add((tuple(sorted(A)), tuple(sorted(B))))
            
            # Condition 3: Message transitions
            elif (A.issubset(message_trans) and B.issubset(message_trans)):
                 XL.add((tuple(sorted(A)), tuple(sorted(B))))
    
    return XL



def mine_local_process(log):
    grouped_log = log.groupby(["case_id"])
    activities = set(grouped_log["context"].apply(list).explode())

    T_I = set(grouped_log.first()["context"])
    T_O = set(grouped_log.last()["context"])



    T_L = set()
    for _, group in grouped_log:
        T_L.update(
            group.loc[group["sender"].isna() & group["receiver"].isna(), "context"]
        )
    
    M_L = activities.difference(T_L)

    helper = log[["context", "h_ctx"]]
    filtered_messages = helper[helper["context"].isin(list(M_L))].drop_duplicates(subset='context', keep='first')
    M_L_set = set(filtered_messages.itertuples(index=False, name=None))
   
    Z_L = local_invocation(log)

    X_L = build_causal_relations(T_L, M_L, grouped_log)
    Y_L = eliminate_duplicates(X_L)

    P_L = {"i_L", "o_L"} 
    
    for (A, B) in Y_L:
        place_name = f"p_{','.join(sorted(A))}_{','.join(sorted(B))}"
        P_L.add(place_name)
    
    # Build communication places (RL)
    R_L = set()
    for (A, B) in Z_L:
        place_name = f"r_{','.join(sorted(A))}_{','.join(sorted(B))}"
        R_L.add(place_name)
    
    # Build flow relations (FL)
    F_L = set()
    
    for act in T_I:
        F_L.add(("i_L", act))
    
    for act in T_O:
        F_L.add((act, "o_L"))
    
    for (A, B) in Y_L:
        place_name = f"p_{','.join(sorted(A))}_{','.join(sorted(B))}"
        for a in A:
            F_L.add((a, place_name))
        for b in B:
            F_L.add((place_name, b))
    
    for (A, B) in Z_L:
        place_name = f"r_{','.join(sorted(A))}_{','.join(sorted(B))}"
        for a in A:
            F_L.add((a, place_name))
        for b in B:
            F_L.add((place_name, b))
    
    return LocalNet(P_L, T_L, F_L, M_L_set, R_L)




def dRma_execution(event_log):
    # Step 1: Create Resource Event Log (REL) containing Communciation Ressource Events (CRE): <event_id, res_id, context, h_ctxt, source_uri, dest_uri>
    REL_log = create_REL(event_log)

    #Step 2: Partition the REL by the Ressources, create a Sublog for each Ressource, containing all it's events
    sub_Logs = {key: sub_df for key, sub_df in REL_log.groupby("res_id")}

    #TODO: Step 3: Divide the Sub-Logs over computational Nodes (in our case, creating threads) and execute the mine_local_Process for each Sub_Log
    LRN = {}
    for key, log in sub_Logs.items():
        local_net = mine_local_process(log)
        LRN[key] = local_net

    print("x")



def main():
    # Your main logic goes here
    
    plan = pm4py.read.read_xes("C:\\Users\\sofyv\\Documents\\Universität\\WiSe24_25\\Praktikum\\processDiscovery\\backend\\default_discovery_plans\\AL-1.xes")
    #plan = pm4py.read.read_xes("C:\\Users\\sofyv\\Documents\\Universität\\WiSe24_25\\Praktikum\\processDiscovery\\backend\\default_discovery_plans\\FP_Log.xes")
    #plan = pm4py.read.read_xes("C:\\Users\\sofyv\\Documents\\Universität\\WiSe24_25\\Praktikum\\processDiscovery\\backend\\default_discovery_plans\\HL.xes")
    #plan = pm4py.read.read_xes("C:\\Users\\sofyv\\Documents\\Universität\\WiSe24_25\\Praktikum\\processDiscovery\\backend\\default_discovery_plans\\IP-4_init_log.xes")
    #plan = pd.read_csv("C:\\Users\\sofyv\\Documents\\Universität\\WiSe24_25\\Praktikum\\processDiscovery\\backend\\FP_FULL_LOG.csv")
    dRma_execution(plan)
    #test_plans()

# This ensures the script runs only when executed directly
if __name__ == "__main__":
    main()
