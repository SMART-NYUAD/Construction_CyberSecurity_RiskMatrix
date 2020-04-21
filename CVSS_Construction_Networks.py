"""
///////////////////////////////////////////////////////////////////////////////      
//Title       : Quantitative vulnerability assessment of construction        //
                network in the construction industry                         //
//Authors     : Bharadwaj R.K.Mantha and Yeojin Jung                         //
//Email       : bmantha at nyu dot edu                                       //
//Affiliation : S.M.A.R.T. Construction Research Group,                      //
//              Division of Engineering,                                     //                 
//				   New York University Abu Dhabi.                               //
///////////////////////////////////////////////////////////////////////////////
"""

# general imports 
import networkx as nx
import pandas as pd
import numpy

class participant(object):
    #participant class with respective CVSS base metric attributes
    def __init__(self, participant_id, participant_type, AV,AC,PR,UI,C,I,A,S):
        self.participant_id = participant_id
        self.participant_type = participant_type
        self.AV = AV
        self.AC = AC
        self.PR = PR
        self.UI = UI        
        self.C = C
        self.I = I
        self.A = A
        self.S = S

def resetToInitial(list_o,list_d):
    #to reset the updated participant metrics to the original values
    for i in range(len(list_o)):
        list_d[i].AV = list_o[i].AV
        list_d[i].AC = list_o[i].AC
        list_d[i].PR = list_o[i].PR
        list_d[i].UI = list_o[i].UI
        list_d[i].C = list_o[i].C
        list_d[i].I = list_o[i].I
        list_d[i].A = list_o[i].A
        list_d[i].S = list_o[i].S
                
def getParticipantMetric(participantName):
    #to get all the participant metrics in readable format
    return participantName.participant_id, participantName.AV, participantName.AC, participantName.PR, participantName.UI, participantName.C, participantName.I, participantName.A, participantName.S

def getAllParticipantMetrics(allParticipants):
    for eachParticipant in allParticipants:
        print(getParticipantMetric(eachParticipant))
    return None

def getParticipantScore(participantName):
    # to calculate CVSS base score based on the metrics
    Exploitability_Score = 8.22*metricAV[participantName.AV]*metricAC[participantName.AC]*metricPR[participantName.PR]*metricUI[participantName.UI]
    #print(Exploitability_Score)
    ISS = (1-(1-metricImpact[participantName.C])*(1-metricImpact[participantName.I])*(1-metricImpact[participantName.A]))
    #print(ISS)
    if(participantName.S == "Unchanged"):
       Impact_Score = 6.42*ISS
    else:
        Impact_Score = 7.52*(ISS-0.029)-3.25*((ISS-0.02)**15)
        #print(Impact_Score)
    if (Impact_Score <= 0):
        BaseScore = 0
    else:
        if (participantName.S == "Unchanged"):
            BaseScore = min((Impact_Score+Exploitability_Score),10)
            BaseScore = round(BaseScore,2)
        else:
            BaseScore = min(1.08*(Impact_Score+Exploitability_Score),10)
            BaseScore = round(BaseScore,2)
    
    #return Exploitability, Impact, fImpact, BaseScore
    return participantName.participant_id, metricAV[participantName.AV], metricAC[participantName.AC], metricPR[participantName.PR], metricUI[participantName.UI], metricImpact[participantName.C],metricImpact[participantName.I], metricImpact[participantName.A], metricScope[participantName.S],BaseScore
    

def propogation(node1, node2):
    # to propogate the vulnerability from node1 to node 2
    # inputs are participant class objects
    # function modifies the respective metric attribute values
    # based on aggregation logic node1 metrics doesnt change
    # node2 metrics get maximum of each of the metrics of the ancestor node (node 1)
    
    #checking AV
    maxValue = max(metricAV[node1.AV], metricAV[node2.AV])
    metric = [key  for (key, value) in metricAV.items() if value == maxValue]
    node2.AV = metric[0]
    
    #checking AV
    maxValue = max(metricAC[node1.AC], metricAC[node2.AC])
    metric = [key  for (key, value) in metricAC.items() if value == maxValue]
    node2.AC = metric[0]
    
    #checking PR
    maxValue = max(metricPR[node1.PR], metricPR[node2.PR])
    metric = [key  for (key, value) in metricPR.items() if value == maxValue]
    node2.PR = metric[0]    

    #checking UI
    maxValue = max(metricUI[node1.UI], metricUI[node2.UI])
    metric = [key  for (key, value) in metricUI.items() if value == maxValue]
    node2.UI = metric[0]  
    
    #checking C
    maxValue = max(metricImpact[node1.C], metricImpact[node2.C])
    metric = [key  for (key, value) in metricImpact.items() if value == maxValue]
    node2.C = metric[0] 

    #checking I
    maxValue = max(metricImpact[node1.I], metricImpact[node2.I])
    metric = [key  for (key, value) in metricImpact.items() if value == maxValue]
    node2.I = metric[0] 
    
    #checking A
    maxValue = max(metricImpact[node1.A], metricImpact[node2.A])
    metric = [key  for (key, value) in metricImpact.items() if value == maxValue]
    node2.A = metric[0] 
    
    return None

def getPathScore_method3(pathScoreList):
    # average method
    # instead of taking worse value from ancestor node it takes avg
    outputList = pathScoreList
    num_edges = len(pathScoreList)
    for i in range(num_edges-1):
        
        if (pathScoreList[i+1] < pathScoreList[i]):
            outputList[i+1] = 0.5 * (pathScoreList[i+1] + pathScoreList[i])
        else:
            outputList[i+1] = pathScoreList[i+1] 
    outputScore = (numpy.prod(outputList))/(10**num_edges)
    #outputScore = round(outputScore,2)
    return outputList, outputScore 

def getPathScore_allMethods(allParticipants):
    # main function that does the following calculations
    # estimates all simple paths from all the nodes to the target node (input)
    # for each of the paths identified the vulnerability propogation is performed
    # effective base scores are calculated based on the updated base metrics
    # an agregated effective base score is calculated for the entire path 
    # final value is the probability of the path getting exploited
    # higher the value, higher the probability and hence higher the chance of getting exploited
    # the path with maximum probability is chosen as the critical path for the network configuration
    
    #pathScore1 = 1 # initialize the value 
    #pathScore2 = 1 # for method 2 which is product of all node values
    output = [] # list of lists which has paths and resp path scores
    pathll_list = []
    for sourceNode in allParticipants:
        #loop over all the nodes except the target node
        if (sourceNode == TargetNode):
            # do nothing if it is target node
            pass
        else:
            for path in nx.all_simple_paths(G,sourceNode,TargetNode):
                # calculate simple paths from source node to target node
                path_list = []
                pathScoreList = []
                # reset all participant scores to initial inputted values
                resetToInitial(allParticipants_o,allParticipants)
                # reset path score values for each of the methods
                pathScore1 = 1
                pathScore2 = 1 
                pathScore3 = 1 
                for eachNode in path:
                    #print(eachNode.participant_id)
                    path_list.append(eachNode.participant_id)
                    eachNodeScore = getParticipantScore(eachNode)[-1]
                    pathScore2 = pathScore2* 0.1*eachNodeScore
                    pathScoreList.append(eachNodeScore)
                pathScore3 = getPathScore_method3(pathScoreList)[1]
                #print("For the path: ", path_list)
                pathScore1 = 0.1*pathScore1*getParticipantScore(sourceNode)[-1] 
                #print("EBS of Ancestor Node is: ", pathScore)
                for i in range(len(path)-1):
                    #print("loop: ", i)
                    #print("before spread")
                    #print(getParticipantScore(path[i+1])[-1])
                    propogation(path[i],path[i+1])
                    #print("after spread")
                    #print(getParticipantScore(path[i+1])[-1])
                    pathScore1 = 0.1*pathScore1*getParticipantScore(path[i+1])[-1]
                    #print(path[i].participant_id)
                    #path[i].reset()
                    #print(pathScore)
                path_ll = get_path_ll(path)
                pathll_list.append(path_ll)
                pathScore1 = round(pathScore1,2)
                pathScore2 = round(pathScore2,2)
                pathScore3 = round(pathScore3,2)
                output.append([path_list, 
                               pathScore1, pathScore2,pathScore3,
                               get_path_score_cat(pathScore1),
                               get_path_score_cat(pathScore2),
                               get_path_score_cat(pathScore3),
                               path_ll
                               ])
                #index_max_score = pathScore_list.index(max(pathScore_list))
                #critical_path = output[index_max_score]
    return output,pathll_list

        
################################### Inputs ####################################
    
# Standard CVSS Base Metric Values - PLEASE DONT CHANGE THESE
metricAV = {'Physical':0.20,'Local':0.55, 'Adjacent': 0.62, 'Network': 0.85}
metricAC = {'High': 0.44, 'Low': 0.77}
#metricPR = {'High': 0.27, 'Low': 0.62, 'None': 0.85} #use these values if Scope = Unchanged and comment the next line
metricPR = {'High': 0.50, 'Low': 0.68, 'None': 0.85} #comment this if Scope = Unchanged
metricUI = {'Required': 0.62, 'None': 0.85}
metricImpact = {'None': 0.0, 'Low': 0.22, 'High': 0.56}
metricScope = {'Unchanged':0.00,'Changed':1.00}

#define participant nodes and edges

# participant class objects 
#NWH = participant('NWH','owner','Physical','High','High','Required','Low','Low','Low','Changed') #medium
#FBL = participant('FBL','Contractor','Local','Low','Low','None','High','High','High','Changed') #high
#CJO = participant('CJO','Worker','Network','Low','Low','None','High','High','High','Changed') #critical

O = participant('O','owner','Physical','High','High','Required','Low','Low','Low','Changed') #medium
A = participant('A','Architect','Local','Low','Low','None','High','High','High','Changed') #high
APM = participant('APM','AsstPM','Local','Low','Low','None','High','High','High','Changed') #high 
SI = participant('SI','Superintendent','Local','Low','Low','None','High','High','High','Changed') #high
PE = participant('PE','Project_Engineer','Local','Low','Low','None','High','High','High','Changed') #high
ME = participant('ME','MEP_Engineer','Local','Low','Low','None','High','High','High','Changed') #high
#F = participant('F','Foreman','Local','Low','Low','None','High','High','High','Changed') #high
F = participant('F','Foreman','Network','Low','Low','None','High','High','High','Changed') #critical

allParticipants = [O,A,APM,SI,PE,ME,F]

# deep copy of the inputted values to help reset the attributes for each loop

O_o = participant('O','owner','Physical','High','High','Required','Low','Low','Low','Changed') #medium
A_o = participant('A','Architect','Local','Low','Low','None','High','High','High','Changed') #high
APM_o = participant('APM','AsstPM','Local','Low','Low','None','High','High','High','Changed') #high 
SI_o = participant('SI','Superintendent','Local','Low','Low','None','High','High','High','Changed') #high
PE_o = participant('PE','Project_Engineer','Local','Low','Low','None','High','High','High','Changed') #high
ME_o = participant('PE','MEP_Engineer','Local','Low','Low','None','High','High','High','Changed') #high
F_o = participant('F','Foreman','Network','Low','Low','None','High','High','High','Changed') #critical

allParticipants_o = [O_o,A_o,APM_o,SI_o,PE_o,ME_o,F_o]

# define the target node in the network
#allSourceNodes = [NWH,FBL]
TargetNode = O

def get_path_score_cat(score):
    if score >= 0.0 and score < 0.20:
        return "Very Low"
    elif score >= 0.20 and score < 0.40:
        return "Low"
    elif score >= 0.40 and score < 0.60:
        return "Moderate"
    elif score >=0.60 and score <= 0.80:
        return "High"
    elif score >=0.80 and score <= 1.00:
        return "Very High"

def get_path_ll_cat(score):
    if score >= 0.0 and score < 0.20:
        return "Very Low"
    elif score >= 0.20 and score < 0.40:
        return "Low"
    elif score >= 0.40 and score < 0.60:
        return "Moderate"
    elif score >=0.60 and score <= 0.80:
        return "High"
    elif score >=0.80 and score <= 1.00:
        return "Very High"


################# more code implementation ############################

#create graph and add nodes and edges
G = nx.Graph()
G.add_nodes_from(allParticipants)
"""
G.add_edges_from([
    (O,APM),(O,SI),
    (F,APM),(F,PE),(F,SI),
    (ME,SI),(ME,PE),
    (A,APM),
    (APM,PE)
])
"""
l1 = 1.0/35.0 # 35 = 1 + 4 + 30
l2 = 4.0/35.0
l3 = 30.0/35.0

G.add_edges_from([
    (O,APM,{'weight': l2}),(O,SI,{'weight': l2}),
    (F,APM,{'weight': l3}),(F,PE,{'weight': l1}),(F,SI,{'weight': l3}),
    (ME,SI,{'weight': l3}),(ME,PE,{'weight': l2}),
    (A,APM,{'weight': l2}),
    (APM,PE,{'weight': l3})
    #(O,A,{'weight': 4.0}),(O,F,{'weight': 4.0})
])
    
# =============================================================================
# all_edges = [e for e in G.edges]
# total_edge_weight = 0
# for each_edge in all_edges:
#     total_edge_weight = total_edge_weight + (G.get_edge_data(each_edge[0],each_edge[1])['weight'])
# print(total_edge_weight)
# =============================================================================

#total_edge_weight = 1.0

def get_path_ll(path):
    current_path_weight = 1
    num_edges = len(path)-1
    for i in range(num_edges):
        #print(current_path_weight)
        current_path_weight = current_path_weight*(G.get_edge_data(path[i],path[i+1])['weight'])
    return round(current_path_weight,7)
#print(get_path_likelihood([O,APM,PE],total_edge_weight))
        
##########################################################################

############### testing and execution ###############################


# output the data in a data frame
print("all paths and scores are: ")

[data,pathll_list] = getPathScore_allMethods(allParticipants)
for i in range(len(data)):
    temp = (pathll_list[i] - min(pathll_list))/(max(pathll_list)-min(pathll_list))
    data[i].append(temp)
    data[i].append(get_path_ll_cat(temp))
print(data)

df = pd.DataFrame.from_records(data)

df.columns = ['Possible Attack Paths','SS1','SS2','SS3',
              'SS1 Category','SS2 Category','SS3 Category',
              'Likelihood Score','Likelihood Score Scaled',
              'Likelihood Category']
df1 = df.sort_values('Likelihood Score Scaled', ascending = False)
print(df1)
df1.to_excel("results.xlsx") 

#reset values because the last node will not get updated otherwise
resetToInitial(allParticipants_o,allParticipants) 

# =============================================================================
# print the scores and metrics of the participants in the network to cross check
#print("")
#for eachPart in allParticipants:
#     print(getParticipantMetric(eachPart))
#     print(getParticipantScore(eachPart))
#     print("")
# =============================================================================
