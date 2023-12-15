import clsx from 'clsx';
import React, { useContext, useEffect, useState } from 'react';
import { Table } from 'react-bootstrap';
import { AppContext } from '../../../AppContext';
import CollapsibleSection from './Components/CollapsibleSection';
import ExtraNodeProps from './Components/ExtraNodeProps';
import MappedNodeProps from './Components/MappedNodeProps';
import NodeCypherLink from './Components/NodeCypherLink';
import NodeCypherNoNumberLink from './Components/NodeCypherNoNumberLink';
import styles from './NodeData.module.css';

const NtfsNodeData = () => {
    const [visible, setVisible] = useState(false);
    const [objectid, setObjectid] = useState(null);
    const [label, setLabel] = useState(null);
    const [domain, setDomain] = useState(null);
    const [nodeProps, setNodeProps] = useState({});
    const context = useContext(AppContext);

    useEffect(() => {
        emitter.on('nodeClicked', nodeClickEvent);

        return () => {
            emitter.removeListener('nodeClicked', nodeClickEvent);
        };
    }, []);

    const nodeClickEvent = (type, id, blocksinheritance, domain) => {
        if (type === 'Fileshare') {
            setVisible(true);
            setObjectid(id);
            setDomain(domain);
            let session = driver.session();
            session
                .run(
                    `MATCH (n:Fileshare {objectid: $objectid}) RETURN n AS node`,
                    {
                        objectid: id,
                    }
                )
                .then((r) => {
                    console.debug('Running query');
                    let props = r.records[0].get('node').properties;
                    setNodeProps(props);
                    setLabel(props.name || objectid);
                    session.close();
                });
        } else {
            setObjectid(null);
            setVisible(false);
        }
    };

    const displayMap = {
        objectid: 'Object ID',
        name : 'Name',
        owned: 'Compromised',
        cifspath : 'Cifs Path',

    };
    return objectid === null ? (
        <div></div>
    ) : (
        <div
            className={clsx(
                !visible && 'displaynone',
                context.darkMode ? styles.dark : styles.light
            )}
        >
            <div className={clsx(styles.dl)}>
                <h5>{label || objectid}</h5>

                <CollapsibleSection header='OVERVIEW'>
                    <div className={styles.itemlist}>
                        <Table>
                            <thead></thead>
                            <tbody className='searchable'>
                                <NodeCypherLink
                                    property='Path to here from owned objects'
                                    target={objectid}
                                    baseQuery={
                                        'MATCH p=shortestPath((n {owned:true})-[*1..]->(m:Fileshare {objectid: $objectid})) WHERE NOT n=m'
                                    }
                                    start={label}
                                />
                                <NodeCypherLinkComplex
                                    property='User with NtfsRead to this share'
                                    target={objectid}
                                    countQuery={
                                        'MATCH p=shortestPath((u:User)-[:NtfsRead|MemberOf*1..]->(m:Fileshare {objectid: $objectid})) WHERE NOT u=m RETURN COUNT(DISTINCT(u))'
                                    }
                                    graphQuery={
                                        'MATCH p=shortestPath((u:User)-[:NtfsRead|MemberOf*1..]->(m:Fileshare {objectid: $objectid})) WHERE NOT u=m RETURN p'
                                    }
                                />

                                <NodeCypherLinkComplex
                                    property='User with NtfsFullControl to this share'
                                    target={objectid}
                                    countQuery={
                                        'MATCH p=shortestPath((u:User)-[:NtfsFullControl|MemberOf*1..]->(m:Fileshare {objectid: $objectid})) WHERE NOT u=m RETURN COUNT(DISTINCT(u))'
                                    }
                                    graphQuery={
                                        'MATCH p=shortestPath((u:User)-[:NtfsFullControl|MemberOf*1..]->(m:Fileshare {objectid: $objectid})) WHERE NOT u=m RETURN p'
                                    }
                                />

                                <NodeCypherLinkComplex
                                    property='User with AceControl to this share'
                                    target={objectid}
                                    countQuery={
                                        'MATCH p=shortestPath((u:User)-[:NtfsAceControl|MemberOf*1..]->(m:Fileshare {objectid: $objectid})) WHERE NOT u=m RETURN COUNT(DISTINCT(u))'
                                    }
                                    graphQuery={
                                        'MATCH p=shortestPath((u:User)-[:NtfsAceControl|MemberOf*1..]->(m:Fileshare {objectid: $objectid})) WHERE NOT u=m RETURN p'
                                    }
                                />
                            </tbody>
                        </Table>
                    </div>
                </CollapsibleSection>

                <MappedNodeProps
                    displayMap={displayMap}
                    properties={nodeProps}
                    label={label}
                />
                <ExtraNodeProps
                    displayMap={displayMap}
                    properties={nodeProps}
                    label={label}
                />

                {/* <Notes objectid={objectid} type='Computer' />
                <NodeGallery
                    objectid={objectid}
                    type='Computer'
                    visible={visible}
                /> */}
            </div>
        </div>
    );
};

NtfsNodeData.propTypes = {};
export default NtfsNodeData;