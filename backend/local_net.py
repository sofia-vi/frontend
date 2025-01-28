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
