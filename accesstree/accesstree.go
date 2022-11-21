package accesstree

import (
	"log"
)

type AccessTree struct {
	Root *AccessTreeNode
}

type AccessTreeNode struct {
	Attribute *int            // only exists if leaf
	Parent    *AccessTreeNode // only exists if not root
	Children  []*AccessTreeNode
	Index     int
	K         int // always 1 if leaf
}

func MakeTree(node *AccessTreeNode) AccessTree {
	// make sure the root has no parent
	node.Parent = nil
	return AccessTree{
		Root: node,
	}
}

func MakeLeaf(attribute int) *AccessTreeNode {
	return &AccessTreeNode{
		Attribute: &attribute,
		Parent:    nil, // will be set by parent
		Children:  make([]*AccessTreeNode, 0),
		Index:     1, // will be set by parent
		K:         1,
	}
}

func MakeBranch(k int, nodes ...*AccessTreeNode) *AccessTreeNode {
	if len(nodes) < k {
		log.Fatalln("error: cannot satisfy tree if k > number of nodes.")
	}

	x := AccessTreeNode{
		Attribute: nil, // branches have no attributes
		Parent:    nil, // will be set by parent
		Children:  make([]*AccessTreeNode, 0),
		Index:     1, // will be set by parent
		K:         k,
	}

	for i, node := range nodes {
		node.Parent = &x
		node.Index = i + 1
		x.Children = append(x.Children, node)
	}

	return &x
}
