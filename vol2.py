#!/venv/volatility3/bin/python
import os
import subprocess
import sys
import logging
import fcntl

# Unset LD_LIBRARY_PATH if it exists
if 'LD_LIBRARY_PATH' in os.environ:
    del os.environ['LD_LIBRARY_PATH']

# Set up logging to a file for capturing errors
logging.basicConfig(filename='/opt/splunk/var/log/splunk/volatility_errors.log', level=logging.ERROR)

def run_volatility(args):
    """Run the Volatility3 script with the provided arguments and capture the output."""
    try:
        # Path to the Volatility3 script
        path_to_volatility = '/opt/tools/volatility/vol.py'

        # Path to the Python 2 interpreter (adjusted as needed)
        python2_interpreter = '/usr/bin/python2.7'

        # Prepare the command with arguments using Python 2
        command = [python2_interpreter, path_to_volatility] + args

        # Execute the command, capturing both stdout and stderr separately
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        # Decode the outputs
        stdout_decoded = stdout.decode()
        stderr_decoded = stderr.decode()

        output_lines = stdout_decoded.splitlines() 
        stdout_decoded = '\n'.join([','.join(line.split()) for line in output_lines])
        print(stdout_decoded)
        # Always return the combined output
        return stdout_decoded, stderr_decoded

    except Exception as e:
        # Log the exception to the external log file
        error_message = f"An unexpected error occurred: {str(e)}"
        logging.error(error_message)
        # Always return the error message to Splunk
        return error_message, ""

def main():
    # Path to the lock file
    lock_file_path = '/tmp/volatility2_script.lock'
    max_processes = 2

    # Open the lock file
    with open(lock_file_path, 'w+') as lock_file:
        try:
            try:
                fcntl.flock(lock_file, fcntl.LOCK_EX)
            except IOError:
                pass

            # Read the current number of processes
            lock_file.seek(0)
            content = lock_file.read().strip()
            current_processes = int(content) if content else 0

            # Check if we can start another instance
            if current_processes >= max_processes:
                print("Maximum number of instances already running. Exiting.")
                sys.exit(1)

            # Increment the process count
            current_processes += 1
            lock_file.seek(0)
            lock_file.write(str(current_processes))
            lock_file.truncate()
            lock_file.flush()

            # Release the lock before running the process
            fcntl.flock(lock_file, fcntl.LOCK_UN)

            # The first argument from Splunk is typically the script name, ignore it
            # Subsequent arguments should be the actual arguments to pass to Volatility
            args = sys.argv[1:]

            # Run Volatility with the given arguments
            stdout_decoded, stderr_decoded = run_volatility(args)
            if stdout_decoded or stderr_decoded:
                combined_output = stdout_decoded + stderr_decoded
                sys.stdout.write(combined_output)

        except IOError:
            # Handle file lock contention by restarting the script
            try:
                fcntl.flock(lock_file, fcntl.LOCK_UN)
                os.execv(__file__, sys.argv)
            except Exception as e:
                logging.error(f"An error occurred while restarting: {str(e)}")
                sys.stdout.write(f"An error occurred while restarting: {str(e)}\n")
                return 0
        except Exception as e:
            logging.error(f"An error occurred: {str(e)}")
            sys.stdout.write(f"An error occurred: {str(e)}\n")
            return 0
        finally:
            try:
                # Reacquire the lock to decrement the process count
                fcntl.flock(lock_file, fcntl.LOCK_EX)

                # Decrement the process count
                lock_file.seek(0)
                current_processes = int(lock_file.read().strip())
                current_processes -= 1
                lock_file.seek(0)
                lock_file.write(str(current_processes))
                lock_file.truncate()
                lock_file.flush()

                # Release the lock
                fcntl.flock(lock_file, fcntl.LOCK_UN)
            except Exception as e:
                logging.error(f"Failed to release the lock: {str(e)}")

if __name__ == "__main__":
    main()
