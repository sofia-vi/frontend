import pm4py
import pandas as pd
import os
from multiprocessing import Pool
  


def test_plans():
    files = os.listdir("C:\\Users\\sofyv\\Documents\\Universität\\WiSe24_25\\Praktikum\\processDiscovery\\backend\\default_discovery_plans")

    for path in files:
        if path != "bpmn":
            p = "C:\\Users\\sofyv\\Documents\\Universität\\WiSe24_25\\Praktikum\\processDiscovery\\backend\\default_discovery_plans\\"
            p += path
            plan =  pm4py.read.read_xes(p)
            plan_update = plan.drop(columns=["time:timestamp"])
            file_name = path.replace(".xes", ".csv")
            plan_update.to_csv(file_name, index=False) 
    
    print(files)

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

            modified_log[["case_id","event_id","res_id","context","h_ctx","sender","receiver","timestamp"]] = merged_log[['case:concept:name', 'event_id', 'org:group', "concept:name","h_ctx","sender","receiver","time:timestamp"]]

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
            modified_log[["case_id","event_id","res_id","context","h_ctx","sender","receiver","timestamp"]] = merged_log[['case:concept:name', 'event_id', 'org:resource', "concept:name","h_ctx","sender","receiver","time:timestamp"]]
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
            modified_log[["case_id","event_id","res_id","context","h_ctx","sender","receiver","timestamp"]] = merged_log[['case:concept:name', 'event_id', 'org:resource', "concept:name","h_ctx","sender","receiver","time:timestamp"]]
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
                    A = A["context"]
                    B = matching_rows.iloc[0]["context"]
                    invocation_set.add((A, B))

    return invocation_set


def mine_local_process(log, resName):
    print(log)

    #get message transitions and places 
    M_L = set()
    for _, group in log.groupby(["case_id"]):
        M_L.update(
            map(tuple, group.loc[group["sender"].notna() & group["receiver"].notna(), ["context", "h_ctx"]].values)
        )
    net, initial_marking, final_marking = pm4py.discovery.discover_petri_net_alpha(log,"context","timestamp","case_id")
    #pm4py.view_petri_net(net, initial_marking, final_marking, format='svg')
    

    for arc in net.arcs:
        if arc.target.name == "end":
            arc.target.name = f"o_{resName}"
        elif arc.source.name == "start":
            arc.source.name = f"i_{resName}"

    ''' 
    Z_L = local_invocation(log)

    #Adding local invocation places

    if len(Z_L) > 0:
        for (A,B) in Z_L:
            hasArc = False
            incoming = None
            outgoing = None
            for arc in net.arcs:
                if arc.target.name == f"({{{repr(A)}}}, {{{repr(B)}}})":
                    hasArc = True
            if not hasArc:
                #TODO: Add place and arcs 
                place = PetriNet.Place(f"({{{repr(A)}}}, {{{repr(B)}}})")
                for transition in net.transitions:
                    if transition.name == A:
                        incoming = transition
                    elif transition.name == B:
                        outgoing = transition

                arcIn = PetriNet.Arc(incoming, place)
                arcOut = PetriNet.Arc(place,outgoing)
                #Add arcs to place
                place.in_arcs.add(arcIn)
                place.out_arcs.add(arcOut)
                net.places.add(place)

                #add arcs to transitions
                incoming.out_arcs.add(arcIn)
                outgoing.in_arcs.add(arcOut)

                #add arcs to petri net
                net.arcs.add(arcIn)
                net.arcs.add(arcOut)
    '''

    pm4py.view_petri_net(net, initial_marking, final_marking, format='svg')
                
    print("X")
    return net, initial_marking, final_marking

from pm4py.objects.petri_net.obj import PetriNet, Marking


def create_final_log(LRN, global_log):
    all_places = set()
    all_arcs = set()
    all_transitions = set()
    transition_dict = dict()
    all_inits = []
    all_final = []
    for key, resource in LRN.items():
        all_places.update(set(resource["net"].places))
        all_arcs.update(set(resource["net"].arcs))
        all_transitions.update(set(resource["net"].transitions))
        for transition in resource["net"].transitions:
            transition_dict[transition.name] = transition
        all_inits.append(resource["initial"])
        all_final.append(resource["final"])
    

    for place in global_log.places:
        if place.name != "start" and place.name != "end":
            in_arcs = place.in_arcs.copy()
            out_arcs = place.out_arcs.copy()
            place.in_arcs.clear()
            place.out_arcs.clear()
            for arc in in_arcs:
                if arc.source.name in transition_dict:
                    in_arc = PetriNet.Arc(transition_dict[arc.source.name], place)
                    place.in_arcs.add(in_arc)
                    transition_dict[arc.source.name].out_arcs.add(in_arc)
                    all_arcs.add(in_arc)
            for arc in out_arcs:
                if arc.target.name in transition_dict:
                    out_arc = PetriNet.Arc(place, transition_dict[arc.target.name])
                    place.in_arcs.add(out_arc)
                    transition_dict[arc.target.name].in_arcs.add(out_arc)
                    all_arcs.add(out_arc)
            all_places.add(place)
            


    net = PetriNet("test", all_places, all_transitions, all_arcs)
    pm4py.view_petri_net(net, all_inits[0], all_final[0], format='svg')
    return net, all_inits, all_final

def get_global_net(log):
    column_set = set(log['context'])
    subsets = {}
    nets ={}
    for entry in column_set:
        subset = log[(log['context'] == entry) | (log['h_ctx'] == entry)]
        if len(set(subset['context'])) > 1:
            subsets[entry] = subset
    
    for key, sublog in subsets.items():
      
        net, initial_marking, final_marking = pm4py.discovery.discover_petri_net_alpha(sublog,"context","timestamp","case_id")
        #pm4py.view_petri_net(net, initial_marking, final_marking, format='svg')
        nets[key] = {"net": net, "initial": initial_marking, "final": final_marking}
    return merge_logs(nets)
    

def merge_logs(logs):
    all_places = set()
    all_arcs = set()
    all_transitions = set()
    all_inits = []
    all_final = []
    for key, resource in logs.items():
        all_places.update(set(resource["net"].places))
        all_arcs.update(set(resource["net"].arcs))
        all_transitions.update(set(resource["net"].transitions))
        all_inits.append(resource["initial"])
        all_final.append(resource["final"])
    net = PetriNet("messages", all_places, all_transitions, all_arcs)
    pm4py.view_petri_net(net, format='svg')
    
    return net

def dRma_execution(event_log):
    # Step 1: Create Resource Event Log (REL) containing Communciation Ressource Events (CRE): <event_id, res_id, context, h_ctxt, source_uri, dest_uri>
    REL_log = create_REL(event_log)

   
    #Step 2: Partition the REL by the Ressources, create a Sublog for each Ressource, containing all it's events
    sub_Logs = {key: sub_df for key, sub_df in REL_log.groupby("res_id")}

    #Step 3: Divide the Sub-Logs over computational Nodes (in our case, creating threads) and execute the mine_local_Process for each Sub_Log
    LRN = {}
    for key, log in sub_Logs.items():
        net, initial_marking, final_marking= mine_local_process(log, key)
        LRN[key] = {"res": key, "net": net, "initial": initial_marking, "final": final_marking}

    #Step 4: Global Process
    global_net = get_global_net(REL_log[REL_log["sender"].notna() & REL_log["receiver"].notna()])

    result = create_final_log(LRN, global_net)

    print("x")



def main():
    # Your main logic goes here
    plan = pm4py.read.read_xes("C:\\Users\\sofyv\\Documents\\Universität\\WiSe24_25\\Praktikum\\processDiscovery\\backend\\default_discovery_plans\\AL-2.xes")

    dRma_execution(plan)

    #pm4py.view_petri_net(net, initial_marking, final_marking, format='svg')
    #test_plans()

# This ensures the script runs only when executed directly
if __name__ == "__main__":
    main()
