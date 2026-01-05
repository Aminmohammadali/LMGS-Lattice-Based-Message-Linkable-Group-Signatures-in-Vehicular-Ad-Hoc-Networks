Description:
In our scheme, we consider three entities: Vehicles, Central System (CS) including the Trusted Authority (TA) and Application Servers (AS), and RSU. In the implementation, the TA runs the key generator and produces the public and secret keys for both the Vehicles and the RSU. Once the TA generates the public parameters, they are uploaded to RSU and CS so that all entities can retrieve them. Therefore, all public and private keys are unique and remain unchanged.

Whenever a vehicle requires its secret parameters, it sends a request to the TA, and the TA provides the tuple $S_1^{(i)}, S_2^{(i)}, S_3^{(i)}$ and $id_i$ which are private group signature keys should verify this expression : 

$
[\mathbf{A} \mid \mathbf{B}+id_i\mathbf{G} \mid \mathbf{B}'] 
\begin{bmatrix}
\mathbf{s}_1^{(i)}\\ 
\mathbf{s}_2^{(i)}\\ 
\mathbf{s}_3^{(i)}
\end{bmatrix} = \mathbf{u}.
$

After receiving these values, the vehicle can generate signature for the messages it wants to send to RSU or other vehicles anonymously.  The user runs the signer code with its secret and public parameters to produce a signature using \texttt{Group_sig_unified.py}, and then sends the result to the verifier (in this case, the RSU). The RSU or any other entity can verify the endorsement using \texttt{Group_sig_unified.py}. One can seperate signature generation and verification process. 
