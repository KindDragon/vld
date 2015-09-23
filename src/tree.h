////////////////////////////////////////////////////////////////////////////////
//
//  Visual Leak Detector - Red-black Tree Template
//  Copyright (c) 2005-2014 VLD Team
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2.1 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
//
//  See COPYING.txt for the full terms of the GNU Lesser General Public License.
//
////////////////////////////////////////////////////////////////////////////////

#pragma once

#ifndef VLDBUILD
#error \
"This header should only be included by Visual Leak Detector when building it from source. \
Applications should never include this header."
#endif

#include "vldheap.h" // Provides internal new and delete operators.
#include "criticalsection.h"

#define TREE_DEFAULT_RESERVE 32 // By default, trees reserve enough space, in advance, for this many nodes.

////////////////////////////////////////////////////////////////////////////////
//
//  The Tree Template Class
//
//    This data structure is the internal data structure behind the lightweight
//    STL-like container classes. This is a red-black tree which provides for
//    fast insert, find, and erase operations.
//
//    The binary tree nodes are overlaid on top of larger chunks of allocated
//    memory (called chunks) which are arranged in a simple linked list. This
//    allows the tree to grow (add nodes) dynamically without incurring a heap
//    hit each time a new node is added.
//
//    The Tree class provides member functions which make it easily adaptable to
//    an STL-like interface so that it can be used as the backend for STL-like
//    container classes.
//
template <typename T>
class Tree
{
public:
    // This is a red-black tree.
    enum color_e {
        red,
        black
    };

    // The node is the basic data structure which the tree is built from.
    struct node_t {
        color_e            color;  // The node's color.
        T                  key;    // The node's value, by which nodes are sorted.
        union {
            struct node_t *left;   // For nodes in the tree, the node's left child.
            struct node_t *next;   // For nodes in the free list, the next node on the free list.
        };
        struct node_t     *parent; // The node's parent.
        struct node_t     *right;  // The node's right child.
    };

    // Reserve capacity for the tree is allocated in large chunks with room for
    // many nodes.
    struct chunk_t {
        struct chunk_t *next;  // Pointer to the next node in the chunk list.
        node_t         *nodes; // Pointer to an array (of variable size) where nodes are stored.
    };

    // Constructor
    Tree ()
    {
        m_freelist   = NULL;
        m_lock.Initialize();
        m_nil.color  = black;
        m_nil.key    = T();
        m_nil.left   = &m_nil;
        m_nil.parent = &m_nil;
        m_nil.right  = &m_nil;
        m_reserve    = TREE_DEFAULT_RESERVE;
        m_root       = &m_nil;
        m_store      = NULL;
        m_storetail  = NULL;
    }

    // Copy constructor - The sole purpose of this constructor's existence is
    //   to ensure that trees are not being inadvertently copied.
    Tree<T> (const Tree<T>& source)
    {
        assert(FALSE); // Do not make copies of trees!
    }

    // Destructor
    ~Tree ()
    {
        chunk_t *cur;
        chunk_t *temp;

        // Free all the chunks in the chunk list.
        m_lock.Enter();
        cur = m_store;
        while (cur != NULL) {
            temp = cur;
            cur = cur->next;
            delete [] temp->nodes;
            delete temp;
        }
        m_lock.Leave();

        m_lock.Delete();
    }

    // operator = - Assignment operator. For efficiency, we want to avoid ever
    //   making copies of Trees (only pointer passing or reference passing
    //   should be performed). The sole purpose of this assignment operator is
    //   to ensure that no copying is being done inadvertently.
    //
    Tree<T>& operator = (const Tree<T> &other)
    {
        // Don't make copies of Trees!
        assert(FALSE);
        return *this;
    }

    // begin - Obtains a pointer to the first node (the node with the smallest
    //   key value) in the tree.
    //
    //  Return Value:
    //
    //    Returns a pointer to the first node in the tree.
    //    
    typename Tree::node_t* begin () const
    {
        node_t *cur;

        CriticalSectionLocker cs(m_lock);
        if (m_root == &m_nil) {
            return NULL;
        }

        cur = m_root;
        while (cur->left != &m_nil) {
            cur = cur->left;
        }

        return cur;
    }

    // erase - Erases the specified node from the tree. Note that this does
    //   not cause the key associated with the erased node to be freed. The
    //   caller is responsible for freeing any dynamically allocated memory
    //   associated with the key.
    //
    //  - node (IN): Pointer to the node to erase from the tree.
    //
    //  Return Value:
    //
    //    None.
    //
    VOID erase (typename Tree::node_t *node)
    {
        node_t *child;
        node_t *cur;
        node_t *erasure;
        node_t *sibling;

        CriticalSectionLocker cs(m_lock);

        if ((node->left == &m_nil) || (node->right == &m_nil)) {
            // The node to be erased has less than two children. It can be directly
            // removed from the tree.
            erasure = node;
        }
        else {
            // The node to be erased has two children. It can only be removed
            // indirectly. The actual node will stay where it is, but it's contents
            // will be replaced by it's in-order successor's contents. The successor
            // node will then be erased. Find the successor.
            erasure = node->right;
            while (erasure->left != &m_nil) {
                erasure = erasure->left;
            }
        }

        // Select the child node which will replace the node to be erased.
        if (erasure->left != &m_nil) {
            child = erasure->left;
        }
        else {
            child = erasure->right;
        }

        // Replace the node to be erased with the selected child.
        child->parent = erasure->parent;
        if (child->parent == &m_nil) {
            // The root of the tree is being erased. The child becomes root.
            m_root = child;
        }
        else {
            if (erasure == erasure->parent->left) {
                erasure->parent->left = child;
            }
            else {
                erasure->parent->right = child;
            }
        }

        if (erasure != node) {
            // The node being erased from the tree is the successor of the actual
            // node to be erased. Replace the contents of the node to be erased
            // with the successor's contents.
            node->key  = erasure->key;
        }

        if (erasure->color == black) {
            // The node being erased from the tree is black. Restructuring of the
            // tree may be needed so that black-height is maintained.
            cur = child;
            while ((cur != m_root) && (cur->color == black)) {
                if (cur == cur->parent->left) {
                    // Current node is a left child.
                    sibling = cur->parent->right;
                    if (sibling->color == red) {
                        // Sibling is red. Rotate sibling up and color it black.
                        sibling->color = black;
                        cur->parent->color = red;
                        _rotateleft(cur->parent);
                        sibling = cur->parent->right;
                    }
                    if ((sibling->left->color == black) && (sibling->right->color == black)) {
                        // Both of sibling's children are black. Color sibling red.
                        sibling->color = red;
                        cur = cur->parent;
                    }
                    else {
                        // At least one of sibling's children is red.
                        if (sibling->right->color == black) {
                            sibling->left->color = black;
                            sibling->color = red;
                            _rotateright(sibling);
                            sibling = cur->parent->right;
                        }
                        sibling->color = cur->parent->color;
                        cur->parent->color = black;
                        sibling->right->color = black;
                        _rotateleft(cur->parent);
                        cur = m_root;
                    }
                }
                else {
                    // Current node is a right child.
                    sibling = cur->parent->left;
                    if (sibling->color == red) {
                        // Sibling is red. Rotate sibling up and color it black.
                        sibling->color = black;
                        cur->parent->color = red;
                        _rotateright(cur->parent);
                        sibling = cur->parent->left;
                    }
                    if ((sibling->left->color == black) && (sibling->right->color == black)) {
                        // Both of sibling's children are black. Color sibling red.
                        sibling->color = red;
                        cur = cur->parent;
                    }
                    else {
                        // At least one of sibling's children is red.
                        if (sibling->left->color == black) {
                            sibling->right->color = black;
                            sibling->color = red;
                            _rotateleft(sibling);
                            sibling = cur->parent->left;
                        }
                        sibling->color = cur->parent->color;
                        cur->parent->color = black;
                        sibling->left->color = black;
                        _rotateright(cur->parent);
                        cur = m_root;
                    }
                }
            }
            cur->color = black;
        }

        // Put the erased node onto the free list.
        erasure->next = m_freelist;
        m_freelist = erasure;
    }

    // erase - Erases the specified key from the tree. Note that this does
    //   not cause the key associated with the erased node to be freed. The
    //   caller is responsible for freeing any dynamically allocated memory
    //   associated with the key.
    //
    //  - key (IN): The key to erase from the tree. This value is treated as
    //      the key for sorting within the tree. It must therefore be of a type
    //      which supports the "<" operator.
    //
    //  Return Value:
    //
    //    None.
    //
    VOID erase (const T &key)
    {
        node_t *node;

        // Find the node to erase.
        CriticalSectionLocker cs(m_lock);
        node = m_root;
        while (node != &m_nil) {
            if (node->key < key) {
                // Go right.
                node = node->right;
            }
            else if (key < node->key) {
                // Go left.
                node = node->left;
            }
            else {
                // Found it.
                erase(node);
                return;
            }
        }

        // 'key' is not in the tree.
    }

    // find - Obtains a pointer to the node corresponding to the specified key.
    //
    //  - key (IN): The value to search for in the tree. This value is treated
    //      as the key for sorting within the tree. It must therefore be of a
    //      type which supports the "<" operator.
    //
    //  Return Value:
    //
    //    Returns a pointer to the node corresponding to the specified key. If
    //    the key is not in the tree, then "find" returns NULL.
    //
    typename Tree::node_t* find (const T &key) const
    {
        node_t *cur;

        CriticalSectionLocker cs(m_lock);
        cur = m_root;
        while (cur != &m_nil) {
            if (cur->key < key) {
                // Go right.
                cur = cur->right;
            }
            else if (key < cur->key) {
                // Go left.
                cur = cur->left;
            }
            else {
                // Found it.
                return cur;
            }
        }

        // 'key' is not in the tree.
        return NULL;
    }

    // insert - Inserts a new key into the tree.
    //
    //  - key (IN): The key to insert into the tree. This value is treated as
    //      the key for sorting within the tree. It must therefore be of a type
    //      which supports the "<" operator.
    //
    //  Return Value:
    //
    //    Returns a pointer to the node corresponding to the newly inserted
    //    key. If an attempt is made to insert a key which is already in the
    //    tree, then NULL is returned and the new key is not inserted.
    //
    typename Tree::node_t* insert (const T &key)
    {
        CriticalSectionLocker cs(m_lock);

        // Find the location where the new node should be inserted..
        node_t  *cur = m_root;
        node_t  *parent = &m_nil;
        while (cur != &m_nil) {
            parent = cur;
            if (cur->key < key) {
                // Go right.
                cur = cur->right;
            }
            else if (key < cur->key) {
                // Go left.
                cur = cur->left;
            }
            else {
                // Keys in the tree must be unique.
                return NULL;
            }
        }

        // Obtain a new node from the free list.
        if (m_freelist == NULL) {
            // Allocate additional storage.
            reserve(m_reserve);
        }
        node_t  *node = m_freelist;
        m_freelist = m_freelist->next;

        // Initialize the new node and insert it.
        node->color  = red;
        node->key    = key;
        node->left   = &m_nil;
        node->parent = parent;
        node->right  = &m_nil;
        if (parent == &m_nil) {
            // The tree is empty. The new node becomes root.
            m_root = node;
        }
        else {
            if (parent->key < key) {
                // New node is a right child.
                parent->right = node;
            }
            else {
                // New node is a left child.
                parent->left = node;
            }
        }

        // Rebalance and/or adjust the tree, if necessary.
        cur = node;
        node_t  *uncle;
        while (cur->parent->color == red) {
            // Double-red violation. Rebalancing/adjustment needed.
            if (cur->parent == cur->parent->parent->left) {
                // Parent is the left child. Uncle is the right child.
                uncle = cur->parent->parent->right;
                if (uncle->color == red) {
                    // Uncle is red. Recolor.
                    cur->parent->parent->color = red;
                    cur->parent->color = black;
                    uncle->color = black;
                    cur = cur->parent->parent;
                }
                else {
                    // Uncle is black. Restructure.
                    if (cur == cur->parent->right) {
                        cur = cur->parent;
                        _rotateleft(cur);
                    }
                    cur->parent->color = black;
                    cur->parent->parent->color = red;
                    _rotateright(cur->parent->parent);
                }
            }
            else {
                // Parent is the right child. Uncle is the left child.
                uncle = cur->parent->parent->left;
                if (uncle->color == red) {
                    // Uncle is red. Recolor.
                    cur->parent->parent->color = red;
                    cur->parent->color = black;
                    uncle->color = black;
                    cur = cur->parent->parent;
                }
                else {
                    // Uncle is black. Restructure.
                    if (cur == cur->parent->left) {
                        cur = cur->parent;
                        _rotateright(cur);
                    }
                    cur->parent->color = black;
                    cur->parent->parent->color = red;
                    _rotateleft(cur->parent->parent);
                }
            }
        }

        // The root node is always colored black.
        m_root->color = black;
        return node;        
    }

    // next - Obtains a pointer to the in-order successor of the specified
    //   node.
    //
    //  - node (IN): Pointer to the node whose in-order successor to retrieve.
    //
    //  Return Value:
    //
    //    Returns a pointer to the node's in-order successor. If the specified
    //    node corresponds to the largest value in the tree, then the specified
    //    node has no successor and "next" will return NULL.
    //
    typename Tree::node_t* next (typename Tree::node_t *node) const
    {
        if (node == NULL)
            return NULL;

        CriticalSectionLocker cs(m_lock);
        node_t* cur;
        if (node->right != &m_nil) {
            // 'node' has a right child. Successor is the far left node in
            // the right subtree.
            cur = node->right;
            while (cur->left != &m_nil) {
                cur = cur->left;
            }
            return cur;
        }
        else if (node->parent != &m_nil) {
            // 'node' has no right child, but does have a parent.
            if (node == node->parent->left) {
                // 'node' is a left child; node's parent is successor.
                return node->parent;
            }
            else {
                // 'node' is a right child.
                cur = node;
                // Go up the tree until we find a parent to the right.
                while (cur->parent != &m_nil) {
                    if (cur == cur->parent->right) {
                        cur = cur->parent;
                        continue;
                    }
                    else {
                        return cur->parent;
                    }
                }

                // There is no parent greater than 'node'. 'node' is the
                // maximum node.
                return NULL;
            }
        }
        else {
            // 'node' is root and root is the maximum node.
            return NULL;
        }
    }

    // prev - Obtains a pointer to the in-order predecessor of the specified
    //   node.
    //
    //  - node (IN): Pointer to the node whose in-order predecessor to retrieve.
    //
    //  Return Value:
    //
    //    Returns a pointer to the node's in-order predecessor. If the specified
    //    node corresponds to the smallest value in the tree, then the specified
    //    node has no predecessor and "prev" will return NULL.
    //
    typename Tree::node_t* prev (typename Tree::node_t *node) const
    {
        if (node == NULL) {
            return NULL;
        }

        CriticalSectionLocker cs(m_lock);
        node_t* cur;
        if (node->left != &m_nil) {
            // 'node' has left child. Predecessor is the far right node in the
            // left subtree.
            cur = node->left;
            while (cur->right != &m_nil) {
                cur = cur->right;
            }
            return cur;
        }
        else if (node->parent != & m_nil) {
            // 'node' has no left child, but does have a parent.
            if (node == node->parent->right) {
                // 'node' is a right child; node's parent is predecessor.
                return node->parent;
            }
            else {
                // 'node is a left child.
                cur = node;
                // Go up the tree until we find a parent to the left.
                while (cur->parent != &m_nil) {
                    if (cur == cur->parent->left) {
                        cur = cur->parent;
                        continue;
                    }
                    else {
                        return cur->parent;
                    }
                }

                // There is no parent less than 'node'. 'node' is the minimum
                // node.
                return NULL;
            }
        }
        else {
            // 'node' is root and root is the minimum node.
            return NULL;
        }
    }

    // reserve - Reserves storage for a number of nodes in advance and/or sets
    //   the number of nodes for which the tree will automatically reserve
    //   storage when the tree needs to "grow" to accomodate new values being
    //   inserted into the tree. If this function is not called to set the
    //   reserve size to a specific value, then a pre-determined default value
    //   will be used. If this function is called when the tree currently has
    //   no reserve storage, then in addition to setting the tree's reserve
    //   value, it will also cause the tree to immediately reserve the
    //   specified amount of storage.
    //
    //  - count (IN): The number of individual nodes' worth of storage to
    //      reserve.
    //
    //  Return Value:
    //
    //    Returns the previously defined reserve value.
    //
    size_t reserve (size_t count)
    {
        chunk_t *chunk;
        size_t   index;
        size_t   oldreserve = m_reserve;

        if (count != m_reserve) {
            if (count < 1) {
                // Minimum reserve size is 1.
                m_reserve = 1;
            }
            else {
                m_reserve = count;
            }
        }

        CriticalSectionLocker cs(m_lock);
        if (m_freelist == NULL) {
            // Allocate additional storage.
            // Link a new chunk into the chunk list.
            chunk = new Tree::chunk_t;
            chunk->nodes = new Tree::node_t [m_reserve];
            chunk->next = NULL;
            if (m_store == NULL) {
                m_store = chunk;
            }
            else {
                m_storetail->next = chunk;
            }
            m_storetail = chunk;

            // Link the individual nodes together to form a new free list.
            for (index = 0; index < m_reserve - 1; index++) {
                chunk->nodes[index].next = &chunk->nodes[index + 1];
            }
            chunk->nodes[index].next = NULL;
            m_freelist = chunk->nodes;
        }

        return oldreserve;
    }

private:
    // _rotateleft: Rotates a pair of nodes counter-clockwise so that the parent
    //   node becomes the left child and the right child becomes the parent.
    //
    //  - parent (IN): Pointer to the parent to rotate about.
    //
    //  Return Value:
    //
    //    None.
    //
    VOID _rotateleft (typename Tree::node_t *parent)
    {
        node_t *child = parent->right;

        // Reassign the child's left subtree to the parent.
        parent->right = child->left;
        if (child->left != &m_nil) {
            child->left->parent = parent;
        }

        // Reassign the child/parent relationship.
        child->parent = parent->parent;
        if (parent->parent == &m_nil) {
            // The child becomes the new root node.
            m_root = child;
        }
        else {
            // Point the grandparent at the child.
            if (parent == parent->parent->left) {
                parent->parent->left = child;
            }
            else {
                parent->parent->right = child;
            }
        }
        child->left = parent;
        parent->parent = child;
    }

    // _rotateright - Rotates a pair of nodes clockwise so that the parent node
    //   becomes the right child and the left child becomes the parent.
    //
    //  - parent (IN): Pointer to the parent to rotate about.
    //
    //  Return Value:
    //
    //    None.
    //
    VOID _rotateright (typename Tree::node_t *parent)
    {
        node_t *child = parent->left;

        // Reassign the child's right subtree to the parent.
        parent->left = child->right;
        if (child->right != &m_nil) {
            child->right->parent = parent;
        }

        // Reassign the child/parent relationship.
        child->parent = parent->parent;
        if (parent->parent == &m_nil) {
            // The child becomes the new root node.
            m_root = child;
        }
        else {
            // Point the grandparent at the child.
            if (parent == parent->parent->left) {
                parent->parent->left = child;
            }
            else {
                parent->parent->right = child;
            }
        }
        child->right = parent;
        parent->parent = child;
    }

    // Private data members.
    node_t                   *m_freelist;  // Pointer to the list of free nodes (reserve storage).
    mutable CriticalSection   m_lock;      // Protects the tree's integrity against concurrent accesses.
    node_t                    m_nil;       // The tree's nil node. All leaf nodes point to this.
    size_t                    m_reserve;   // The size (in nodes) of the chunks of reserve storage.
    node_t                   *m_root;      // Pointer to the tree's root node.
    chunk_t                  *m_store;     // Pointer to the start of the chunk list.
    chunk_t                  *m_storetail; // Pointer to the end of the chunk list.
};
