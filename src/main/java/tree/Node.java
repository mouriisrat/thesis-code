package tree;

import com.n1analytics.paillier.EncodedNumber;

public class Node {
    public String id;
    public EncodedNumber[] data;
    public Node left, right, parent, next;
}

