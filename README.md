\section*{Repository Roadmap}

This repository implements a group signature scheme using Python and C scripts. The system is composed of multiple scripts that work together for parameter generation, signature creation, and verification.

\subsection*{Scripts Overview}

\textbf{1. \texttt{GS\_merged\_params.py}}  
\begin{itemize}
    \item Generates the parameters required for signing and verification in the form of $As = t$.
    \item Defines matrix and vector dimensions, polynomial ring $\mathcal{R}_q$, and boundary values.
    \item Each execution produces a \texttt{.h} file containing public keys and other parameters.
    \item \textbf{Usage:} Run this script once during the initialization phase. If any parameters are updated, re-run to generate a new \texttt{.h} file for the signer and verifier.
\end{itemize}

\textbf{2. \texttt{Group\_sig\_unified.py}}  
\begin{itemize}
    \item Allows vehicles to generate a signature on a message of the form \texttt{ts || message} using their assigned secret keys.
    \item Verifies received signatures using the public keys stored in \texttt{GS\_merged\_params.h}.
\end{itemize}

\textbf{3. \texttt{Group\_sig\_unified1000.py}}  
\begin{itemize}
    \item Performs 1,000 iterations of signature generation to measure average execution time and signature size.
\end{itemize}

\section*{Description of the Scheme}

The system consists of three main entities:  
\begin{enumerate}
    \item Vehicles
    \item Central System (CS), including the Trusted Authority (TA) and Application Servers (AS)
    \item Roadside Units (RSU)
\end{enumerate}

\subsection*{Key Generation and Distribution}
\begin{itemize}
    \item The TA generates public and private keys for both vehicles and RSUs.
    \item Public parameters are uploaded to RSU and CS, enabling all entities to access them.
    \item All keys are unique and remain unchanged once generated.
\end{itemize}

\subsection*{Vehicle Secret Parameters}
\begin{itemize}
    \item When a vehicle requires its secret parameters, it requests them from the TA.
    \item The TA provides the tuple $(S_1^{(i)}, S_2^{(i)}, S_3^{(i)}, id_i)$, which are the private group signature keys.
    \item These keys satisfy the following equation:
\[
[\mathbf{A} \mid \mathbf{B} + id_i \mathbf{G} \mid \mathbf{B}'] 
\begin{bmatrix}
\mathbf{s}_1^{(i)}\\ 
\mathbf{s}_2^{(i)}\\ 
\mathbf{s}_3^{(i)}
\end{bmatrix} = \mathbf{u}.
\]
\end{itemize}

\subsection*{Signature Generation and Verification}
\begin{itemize}
    \item Vehicles use their secret parameters to generate anonymous signatures on messages intended for RSUs or other vehicles.
    \item Signature generation and verification are handled by \texttt{Group\_sig\_unified.py}.
    \item The RSU or any other entity can verify signatures using the public parameters.
    \item Signing and verification processes can be executed independently.
\end{itemize}
